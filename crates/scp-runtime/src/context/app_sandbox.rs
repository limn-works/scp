//! App sandboxing: capability declaration, scoped handles, and bind-time validation.
//!
//! Implements spec sections 8.4.1 (Capability Declaration Wire Format) and 8.4.2
//! (SDK-Level Enforcement). Apps interact with the protocol exclusively through
//! scoped handles that restrict API access to declared capabilities.
//!
//! # Architecture
//!
//! 1. **`CapabilityDeclaration`** -- Wire format for app capability requests (8.4.1).
//!    Signed by the app publisher's Ed25519 key. Validated at bind time.
//!
//! 2. **`ScopedHandle`** -- A capability-restricted context handle (8.4.2).
//!    Wraps a `ContextHandle` with a whitelist of allowed capabilities.
//!    All protocol operations check the whitelist before delegating.
//!
//! 3. **`validate_declaration()`** -- All-or-nothing bind-time validation.
//!    Checks every requested capability against the context ceiling AND
//!    the agent's role capabilities. Rejects the entire declaration if
//!    any single capability is denied.
//!
//! # Security invariants
//!
//! - No capability escalation after binding (8.4.2 rule 4).
//! - Scoped handles are not interchangeable (8.4.2 rule 5).
//! - `CapabilityDenied` is a hard enforcement boundary, not a suggestion.
//!
//! See spec sections 8.4.1 and 8.4.2 for full details.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ContextHandle;
use scp_did::DID;
use scp_protocol::context::roles::Capability;

// ---------------------------------------------------------------------------
// SandboxError
// ---------------------------------------------------------------------------

/// Errors produced by app sandboxing operations.
///
/// Error codes follow the `SCP-CTX-` prefix (range 2050-2059).
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// An API call was attempted that exceeds the app's declared capabilities.
    ///
    /// This is a hard enforcement boundary (spec 8.4.2 rule 3): the SDK MUST
    /// reject API calls that exceed the app's declared capabilities at the
    /// call site. The rejection is immediate and returns this error.
    #[error("capability denied: {required} not granted to app {app_did}")]
    CapabilityDenied {
        /// The capability that was required for the operation.
        required: Capability,
        /// The DID of the app that attempted the operation.
        app_did: DID,
    },

    /// The capability declaration is structurally invalid.
    ///
    /// Returned when the declaration fails structural validation (e.g.,
    /// empty capabilities list, `app_name` too long, invalid `scp_version`).
    #[error("invalid declaration: {0}")]
    InvalidDeclaration(String),

    /// The Ed25519 signature on the capability declaration is invalid.
    ///
    /// Returned when the signature does not verify against the `app_id`'s
    /// public key over the JCS-canonical JSON of the declaration.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// One or more requested capabilities exceed the context's capability
    /// ceiling or the agent's role.
    ///
    /// Returned during bind-time validation when any capability in the
    /// declaration is not present in the context's ceiling or the agent's
    /// role capabilities. The rejection is all-or-nothing per spec 8.4.1
    /// step 4, and includes the full `denied_capabilities` array listing
    /// every capability that failed and why.
    #[error(
        "ceiling exceeded: {}",
        DeniedCapability::format_list(denied_capabilities)
    )]
    CeilingExceeded {
        /// All capabilities that were denied, with per-capability reasons.
        denied_capabilities: Vec<DeniedCapability>,
    },

    /// Serialization or deserialization failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
}

// ---------------------------------------------------------------------------
// CapabilityConstraint
// ---------------------------------------------------------------------------

/// Optional constraints on a capability (rate limits, size limits, type restrictions).
///
/// App-defined; the protocol validates that constraints are a subset of the
/// context's ceiling. See spec 8.4.1 `capabilities[].constraints`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityConstraint {
    /// Maximum message size in bytes, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_message_size: Option<u64>,
    /// Maximum invocations per minute, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_invocations_per_minute: Option<u32>,
    /// Allowed media types, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_types: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// CapabilityEntry
// ---------------------------------------------------------------------------

/// A single capability entry in a capability declaration.
///
/// Maps to the `capabilities[]` array elements in spec 8.4.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEntry {
    /// SCP resource URI. Format: `scp:ctx:{context_id}/{capability_category}`.
    pub resource: String,
    /// Actions requested on the resource: `"read"`, `"write"`, `"invoke"`, `"admin"`.
    pub actions: Vec<String>,
    /// Optional constraints on the capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<CapabilityConstraint>,
}

impl CapabilityEntry {
    /// Extracts the `Capability` values implied by this entry.
    ///
    /// Parses the resource URI suffix and actions to produce the set of
    /// protocol `Capability` variants this entry requests.
    #[must_use]
    pub fn to_capabilities(&self) -> Vec<Capability> {
        // Extract the capability category from the resource URI.
        // Format: scp:ctx:{context_id}/{category} or scp:ctx:{context_id}/tools/{outlet_id}
        let category = self.resource.rsplit('/').next().unwrap_or(&self.resource);

        // Check if this is a tools/{outlet_id} resource
        let parts: Vec<&str> = self.resource.split('/').collect();
        let is_tool = parts.len() >= 2 && parts[parts.len() - 2] == "tools";

        let mut capabilities = Vec::new();

        for action in &self.actions {
            match (category, action.as_str(), is_tool) {
                (_, "invoke", true) => {
                    capabilities.push(Capability::OutletCall(category.to_owned()));
                }
                ("messaging" | "members", "read", _) => {
                    capabilities.push(Capability::MessagesRead);
                }
                ("messaging", "write", _) => capabilities.push(Capability::MessagesWrite),
                ("members", "write" | "admin", _) => {
                    capabilities.push(Capability::MemberInvite);
                }
                ("tools", "invoke", _) => capabilities.push(Capability::OutletCallAll),
                ("tools", "register" | "admin", _) => {
                    capabilities.push(Capability::OutletRegister);
                }
                ("governance", "write", _) => capabilities.push(Capability::GovernancePropose),
                ("governance", "admin", _) => {
                    capabilities.push(Capability::GovernancePropose);
                    capabilities.push(Capability::GovernanceVote);
                }
                ("roles", "admin", _) => capabilities.push(Capability::RoleAssign),
                ("context", "admin", _) => capabilities.push(Capability::ContextClose),
                ("bridging", _, _) => capabilities.push(Capability::Bridging),
                ("media", "voice", _) => capabilities.push(Capability::MediaVoice),
                ("media", "video", _) => capabilities.push(Capability::MediaVideo),
                ("media", "screen_share", _) => capabilities.push(Capability::MediaScreenShare),
                ("metadata", "write" | "admin", _) => {
                    capabilities.push(Capability::MetadataEdit);
                }
                _ => {
                    // Map unknown categories to Custom capability
                    capabilities.push(Capability::Custom(format!("{category}:{action}")));
                }
            }
        }

        capabilities
    }
}

// ---------------------------------------------------------------------------
// CapabilityDeclaration
// ---------------------------------------------------------------------------

/// Maximum length of `app_name` in UTF-8 bytes (spec 8.4.1).
pub const MAX_APP_NAME_BYTES: usize = 128;

/// Maximum number of capability entries (spec 8.4.1).
pub const MAX_CAPABILITY_ENTRIES: usize = 64;

/// Current SCP protocol version for declarations.
pub const CURRENT_SCP_VERSION: &str = "1.0";

/// App capability declaration wire format (spec 8.4.1).
///
/// A structured, machine-readable manifest of what protocol capabilities
/// an app needs. The declaration is signed by the app publisher's Ed25519
/// key and validated at bind time against the context's capability ceiling
/// and the agent's role.
///
/// # Wire format
///
/// The canonical serialization uses JCS (RFC 8785) for signature computation.
/// The `signature` field is excluded from the canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDeclaration {
    /// SCP protocol version this declaration targets. Format: `"MAJOR.MINOR"`.
    pub scp_version: String,
    /// DID of the app publisher. Used for trust evaluation and revocation.
    pub app_id: DID,
    /// Human-readable app name. Maximum 128 UTF-8 bytes.
    pub app_name: String,
    /// App version. `SemVer` format (`MAJOR.MINOR.PATCH`).
    pub app_version: String,
    /// List of requested capabilities. Minimum 1, maximum 64 entries.
    pub capabilities: Vec<CapabilityEntry>,
    /// Minimum context role required for this app to function.
    pub min_role: String,
    /// Ed25519 signature over canonical JSON (RFC 8785 JCS) of the declaration
    /// with the `signature` field removed.
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// Serde helper for hex-encoded byte vectors in the signature field.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

impl CapabilityDeclaration {
    /// Computes the canonical bytes for signature verification.
    ///
    /// Returns the RFC 8785 JCS-canonical JSON serialization of the
    /// declaration with the `signature` field excluded, as required by
    /// spec 8.4.1.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::SerializationFailed` if JSON serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SandboxError> {
        // Create a version without the signature for canonical serialization.
        // We serialize to a serde_json::Value, remove the signature field,
        // then serialize to sorted-key canonical JSON.
        let mut value = serde_json::to_value(self)
            .map_err(|e| SandboxError::SerializationFailed(e.to_string()))?;

        // Remove the signature field for canonical form.
        if let serde_json::Value::Object(ref mut map) = value {
            map.remove("signature");
        }

        // RFC 8785 JCS canonical serialization for cross-implementation
        // deterministic hashing.
        canonical_json_bytes(&value)
    }

    /// Verifies the Ed25519 signature against the `app_id`'s public key.
    ///
    /// Extracts the public key from the `app_id` DID (which must be a
    /// `did:dht:` or `did:key:` with an Ed25519 key) and verifies the
    /// signature over the canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::SignatureVerificationFailed` if the signature
    /// is invalid, or `SandboxError::InvalidDeclaration` if the DID format
    /// is unsupported.
    pub fn verify(&self) -> Result<(), SandboxError> {
        use ed25519_dalek::Verifier;

        let canonical = self.canonical_bytes()?;

        // Extract public key bytes from the DID.
        let pubkey_bytes = extract_ed25519_pubkey_from_did(&self.app_id)?;

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| SandboxError::SignatureVerificationFailed)?;

        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| SandboxError::SignatureVerificationFailed)?;

        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(&canonical, &signature)
            .map_err(|_| SandboxError::SignatureVerificationFailed)
    }

    /// Validates the structural correctness of the declaration.
    ///
    /// Checks:
    /// - `scp_version` major version matches current.
    /// - `app_name` is within the 128 UTF-8 byte limit.
    /// - `capabilities` has between 1 and 64 entries.
    /// - All capability entries have at least one action.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::InvalidDeclaration` with a descriptive message.
    pub fn validate_structure(&self) -> Result<(), SandboxError> {
        // Check SCP version compatibility (same major version).
        let decl_major = self.scp_version.split('.').next().unwrap_or("0");
        let current_major = CURRENT_SCP_VERSION.split('.').next().unwrap_or("0");
        if decl_major != current_major {
            return Err(SandboxError::InvalidDeclaration(format!(
                "incompatible scp_version: declaration targets {}, SDK supports {}",
                self.scp_version, CURRENT_SCP_VERSION
            )));
        }

        // Check app_name length.
        if self.app_name.len() > MAX_APP_NAME_BYTES {
            return Err(SandboxError::InvalidDeclaration(format!(
                "app_name exceeds {} UTF-8 bytes (got {})",
                MAX_APP_NAME_BYTES,
                self.app_name.len()
            )));
        }

        if self.app_name.is_empty() {
            return Err(SandboxError::InvalidDeclaration(
                "app_name must not be empty".to_owned(),
            ));
        }

        // Check capabilities count.
        if self.capabilities.is_empty() {
            return Err(SandboxError::InvalidDeclaration(
                "capabilities must have at least 1 entry".to_owned(),
            ));
        }
        if self.capabilities.len() > MAX_CAPABILITY_ENTRIES {
            return Err(SandboxError::InvalidDeclaration(format!(
                "capabilities exceeds maximum of {} entries (got {})",
                MAX_CAPABILITY_ENTRIES,
                self.capabilities.len()
            )));
        }

        // Check each entry has at least one action.
        for (i, entry) in self.capabilities.iter().enumerate() {
            if entry.actions.is_empty() {
                return Err(SandboxError::InvalidDeclaration(format!(
                    "capabilities[{i}] must have at least 1 action"
                )));
            }
        }

        // Check min_role is non-empty.
        if self.min_role.is_empty() {
            return Err(SandboxError::InvalidDeclaration(
                "min_role must not be empty".to_owned(),
            ));
        }

        Ok(())
    }

    /// Returns all `Capability` values requested by this declaration.
    #[must_use]
    pub fn requested_capabilities(&self) -> Vec<Capability> {
        self.capabilities
            .iter()
            .flat_map(CapabilityEntry::to_capabilities)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ScopedHandle
// ---------------------------------------------------------------------------

/// A capability-restricted context handle (spec 8.4.2).
///
/// Wraps a `ContextHandle` with a whitelist of allowed capabilities. All
/// protocol operations check the whitelist before delegating to the inner
/// handle. An app cannot access protocol operations beyond its declared
/// capabilities.
///
/// # No escalation guarantee
///
/// Once created, a `ScopedHandle` cannot gain additional capabilities. The
/// only way to expand an app's capabilities is to re-register with a new
/// signed declaration from the publisher (spec 8.4.2 rule 4).
///
/// # Isolation
///
/// Each app receives its own `ScopedHandle`. Scoped handles are not
/// interchangeable -- an app cannot use another app's handle to access
/// capabilities it did not declare (spec 8.4.2 rule 5).
#[derive(Debug, Clone)]
pub struct ScopedHandle {
    /// The inner context handle.
    inner: ContextHandle,
    /// The set of allowed capabilities for this app binding.
    allowed_capabilities: HashSet<Capability>,
    /// The DID of the app this handle is scoped for.
    app_did: DID,
    /// The validated declaration that produced this handle.
    declaration: CapabilityDeclaration,
}

impl ScopedHandle {
    /// Creates a new scoped handle with the given capability whitelist.
    ///
    /// This is intentionally `pub(crate)` -- only `validate_declaration()`
    /// should create scoped handles to maintain the security invariant
    /// that all handles are backed by validated declarations.
    pub(crate) const fn new(
        inner: ContextHandle,
        allowed_capabilities: HashSet<Capability>,
        app_did: DID,
        declaration: CapabilityDeclaration,
    ) -> Self {
        Self {
            inner,
            allowed_capabilities,
            app_did,
            declaration,
        }
    }

    /// Returns the inner context handle.
    ///
    /// This is intentionally `pub(crate)` to prevent apps from bypassing
    /// capability checks by extracting the raw handle.
    #[allow(dead_code)]
    pub(crate) const fn inner(&self) -> &ContextHandle {
        &self.inner
    }

    /// Returns the context ID.
    #[must_use]
    pub fn context_id(&self) -> &str {
        self.inner.context_id()
    }

    /// Returns the app DID this handle is scoped for.
    #[must_use]
    pub const fn app_did(&self) -> &DID {
        &self.app_did
    }

    /// Returns the set of allowed capabilities.
    #[must_use]
    pub const fn allowed_capabilities(&self) -> &HashSet<Capability> {
        &self.allowed_capabilities
    }

    /// Returns a reference to the validated declaration.
    #[must_use]
    pub const fn declaration(&self) -> &CapabilityDeclaration {
        &self.declaration
    }

    /// Checks whether a specific capability is allowed.
    #[must_use]
    pub fn has_capability(&self, capability: &Capability) -> bool {
        self.allowed_capabilities.contains(capability)
    }

    /// Checks a capability and returns an error if denied.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if the capability is not
    /// in the allowed set.
    pub fn check_capability(&self, required: &Capability) -> Result<(), SandboxError> {
        if self.allowed_capabilities.contains(required) {
            Ok(())
        } else {
            Err(SandboxError::CapabilityDenied {
                required: required.clone(),
                app_did: self.app_did.clone(),
            })
        }
    }

    /// Checks `MessagesRead` capability before allowing message reading.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `MessagesRead` is not granted.
    pub fn check_read_messages(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::MessagesRead)
    }

    /// Checks `MessagesWrite` capability before allowing message sending.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `MessagesWrite` is not granted.
    pub fn check_send_message(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::MessagesWrite)
    }

    /// Checks `GovernancePropose` capability before allowing governance proposals.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `GovernancePropose` is not granted.
    pub fn check_propose_governance_action(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::GovernancePropose)
    }

    /// Checks `GovernanceVote` capability before allowing governance votes.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `GovernanceVote` is not granted.
    pub fn check_governance_vote(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::GovernanceVote)
    }

    /// Checks `OutletCallAll` or `OutletCall(outlet_id)` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if neither `OutletCallAll` nor
    /// `OutletCall(outlet_id)` is granted.
    pub fn check_outlet_invoke(&self, outlet_id: &str) -> Result<(), SandboxError> {
        if self
            .allowed_capabilities
            .contains(&Capability::OutletCallAll)
        {
            return Ok(());
        }
        self.check_capability(&Capability::OutletCall(outlet_id.to_owned()))
    }

    /// Checks `OutletRegister` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `OutletRegister` is not granted.
    pub fn check_outlet_register(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::OutletRegister)
    }

    /// Checks `MemberInvite` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `MemberInvite` is not granted.
    pub fn check_member_invite(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::MemberInvite)
    }

    /// Checks `MemberRemove` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `MemberRemove` is not granted.
    pub fn check_member_remove(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::MemberRemove)
    }

    /// Checks `RoleAssign` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `RoleAssign` is not granted.
    pub fn check_role_assign(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::RoleAssign)
    }

    /// Checks `ContextClose` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `ContextClose` is not granted.
    pub fn check_context_close(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::ContextClose)
    }

    /// Checks `Bridging` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `Bridging` is not granted.
    pub fn check_bridging(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::Bridging)
    }

    /// Checks `MetadataEdit` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `MetadataEdit` is not granted.
    pub fn check_metadata_edit(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::MetadataEdit)
    }

    /// Checks `MemberBan` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `MemberBan` is not granted.
    pub fn check_member_ban(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::MemberBan)
    }

    /// Checks `ChildContextCreate` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `ChildContextCreate` is not granted.
    pub fn check_child_context_create(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::ChildContextCreate)
    }

    /// Checks `MediaVoice` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `MediaVoice` is not granted.
    pub fn check_media_voice(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::MediaVoice)
    }

    /// Checks `MediaVideo` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `MediaVideo` is not granted.
    pub fn check_media_video(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::MediaVideo)
    }

    /// Checks `MediaScreenShare` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `MediaScreenShare` is not granted.
    pub fn check_media_screen_share(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::MediaScreenShare)
    }

    /// Checks `OutletInterface` capability.
    ///
    /// # Errors
    ///
    /// Returns `SandboxError::CapabilityDenied` if `OutletInterface` is not granted.
    pub fn check_outlet_interface(&self) -> Result<(), SandboxError> {
        self.check_capability(&Capability::OutletInterface)
    }
}

// ---------------------------------------------------------------------------
// DeniedCapability
// ---------------------------------------------------------------------------

/// Information about a denied capability in a failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedCapability {
    /// The capability that was denied.
    pub capability: Capability,
    /// The reason it was denied.
    pub reason: DenialReason,
}

impl DeniedCapability {
    /// Formats a list of denied capabilities for error messages.
    #[must_use]
    pub fn format_list(denied: &[Self]) -> String {
        denied
            .iter()
            .map(|d| format!("{} ({})", d.capability, d.reason))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The reason a capability was denied during validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// The capability is not in the context's capability ceiling.
    NotInCeiling,
    /// The capability is not granted by the agent's role.
    NotInRole,
}

impl std::fmt::Display for DenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInCeiling => write!(f, "not in context ceiling"),
            Self::NotInRole => write!(f, "not granted by agent role"),
        }
    }
}

// ---------------------------------------------------------------------------
// validate_declaration
// ---------------------------------------------------------------------------

/// Validates a capability declaration against a context ceiling and role capabilities.
///
/// Implements the all-or-nothing bind-time validation described in spec 8.4.1:
///
/// 1. Verify `scp_version` is compatible.
/// 2. Verify `signature` against `app_id`.
/// 3. For each requested capability, check that it exists in the context's
///    ceiling AND the agent's role includes it.
/// 4. If all capabilities are grantable, accept. If any is denied, reject all.
///
/// On success, returns a `ScopedHandle` with exactly the granted capabilities.
///
/// # Arguments
///
/// * `declaration` -- The app's capability declaration.
/// * `context_ceiling` -- The context's capability ceiling (maximum allowed capabilities).
/// * `role_capabilities` -- The agent's role-granted capabilities in this context.
/// * `context_handle` -- The context handle to wrap in a scoped handle.
///
/// # Errors
///
/// Returns `SandboxError` on any validation failure:
/// - `InvalidDeclaration` -- structural validation failed.
/// - `SignatureVerificationFailed` -- Ed25519 signature verification failed.
/// - `CeilingExceeded` -- a requested capability exceeds the ceiling or role.
pub fn validate_declaration(
    declaration: &CapabilityDeclaration,
    context_ceiling: &[Capability],
    role_capabilities: &[Capability],
    context_handle: ContextHandle,
) -> Result<ScopedHandle, SandboxError> {
    // Step 1: Structural validation.
    declaration.validate_structure()?;

    // Step 2: Signature verification.
    declaration.verify()?;

    // Step 3: Capability validation (all-or-nothing).
    let ceiling_set: HashSet<&Capability> = context_ceiling.iter().collect();
    let role_set: HashSet<&Capability> = role_capabilities.iter().collect();

    let requested = declaration.requested_capabilities();
    let mut denied: Vec<DeniedCapability> = Vec::new();

    for cap in &requested {
        if !ceiling_set.contains(cap) {
            // Check if OutletCallAll covers OutletCall(specific)
            if matches!(cap, Capability::OutletCall(_))
                && ceiling_set.contains(&Capability::OutletCallAll)
            {
                // OutletCallAll in ceiling covers specific OutletCall
            } else {
                denied.push(DeniedCapability {
                    capability: cap.clone(),
                    reason: DenialReason::NotInCeiling,
                });
            }
        }
        if !role_set.contains(cap) {
            // Check if OutletCallAll covers OutletCall(specific)
            if matches!(cap, Capability::OutletCall(_))
                && role_set.contains(&Capability::OutletCallAll)
            {
                // OutletCallAll in role covers specific OutletCall
            } else {
                denied.push(DeniedCapability {
                    capability: cap.clone(),
                    reason: DenialReason::NotInRole,
                });
            }
        }
    }

    // All-or-nothing: if ANY capability is denied, reject ALL (spec 8.4.1 step 4).
    // The full denied list is returned so callers can report which capabilities
    // failed and why.
    if !denied.is_empty() {
        return Err(SandboxError::CeilingExceeded {
            denied_capabilities: denied,
        });
    }

    // Step 4: Create scoped handle with exactly the granted capabilities.
    let allowed: HashSet<Capability> = requested.into_iter().collect();

    Ok(ScopedHandle::new(
        context_handle,
        allowed,
        declaration.app_id.clone(),
        declaration.clone(),
    ))
}

// ---------------------------------------------------------------------------
// AppBindEvent / AppUnbindEvent (event log entries)
// ---------------------------------------------------------------------------

/// Event log entry for when an app is bound to a context.
///
/// Recorded in the context's event log at bind time for auditability
/// (spec 8.4.2). Context members can inspect which apps are bound and
/// what capabilities they hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBindEvent {
    /// The DID of the app that was bound.
    pub app_did: DID,
    /// The capabilities granted to the app.
    pub capabilities: Vec<Capability>,
    /// The app name from the declaration.
    pub app_name: String,
    /// The app version from the declaration.
    pub app_version: String,
}

/// Event log entry for when an app is unbound from a context.
///
/// Recorded in the context's event log when an app is removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUnbindEvent {
    /// The DID of the app that was unbound.
    pub app_did: DID,
}

/// Formats an `AppBindEvent` as an event log string.
///
/// Returns a string suitable for appending to the context's Merkle event log
/// via `ContextEventLogProvider::append_event`.
#[must_use]
pub fn format_bind_event(event: &AppBindEvent) -> String {
    let cap_names: Vec<String> = event
        .capabilities
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    format!(
        "AppBound:{}:{}:{}:[{}]",
        event.app_did,
        event.app_name,
        event.app_version,
        cap_names.join(",")
    )
}

/// Formats an `AppUnbindEvent` as an event log string.
#[must_use]
pub fn format_unbind_event(event: &AppUnbindEvent) -> String {
    format!("AppUnbound:{}", event.app_did)
}

// ---------------------------------------------------------------------------
// Helper: canonical JSON serialization
// ---------------------------------------------------------------------------

/// Produces RFC 8785 (JCS) canonical JSON bytes from a `serde_json::Value`.
///
/// Delegates to [`scp_protocol::jcs::to_vec`] which uses `serde_json_canonicalizer`
/// for true RFC 8785 compliance (key sorting, number formatting, escaping).
fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, SandboxError> {
    scp_protocol::jcs::to_vec(value).map_err(SandboxError::SerializationFailed)
}

// ---------------------------------------------------------------------------
// Helper: extract Ed25519 public key from DID
// ---------------------------------------------------------------------------

/// Extracts the Ed25519 public key bytes from a DID string.
///
/// Supports `did:dht:` (z-base-32 encoded) and `did:key:` (multicodec z58btc
/// encoded) formats.
///
/// # Errors
///
/// Returns `SandboxError::InvalidDeclaration` if the DID format is unsupported
/// or the key cannot be decoded.
fn extract_ed25519_pubkey_from_did(did: &DID) -> Result<[u8; 32], SandboxError> {
    let did_str = did.as_ref();

    if did_str.starts_with("did:dht:") {
        // did:dht encodes the Ed25519 public key as z-base-32 in the DID
        // suffix (`did:dht:z<z-base-32>`). Delegate to the single hardened
        // `scp-did` parser so prefix handling, the 32-byte length check, AND
        // z-base-32 canonicality all come from ONE place, identical to the
        // native identity/FFI decoders (single-parser parity). The prior inline
        // code stripped only "did:dht:" (not the multibase 'z'), leaving the 'z'
        // in the decoded payload → 33 bytes → it rejected EVERY valid did:dht
        // DID; delegation fixes that and adds the canonicality guard.
        scp_did::extract_public_key_from_did(did_str).map_err(SandboxError::InvalidDeclaration)
    } else if let Some(id_part) = did_str.strip_prefix("did:key:z") {
        // did:key uses base58btc encoding with a multicodec prefix.
        // Ed25519 multicodec prefix is 0xed01.
        let decoded = bs58::decode(id_part).into_vec().map_err(|_| {
            SandboxError::InvalidDeclaration(format!(
                "failed to decode base58btc from did:key: {did_str}"
            ))
        })?;
        // Check multicodec prefix (0xed, 0x01 for Ed25519).
        if decoded.len() < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
            return Err(SandboxError::InvalidDeclaration(format!(
                "did:key multicodec prefix is not Ed25519: {did_str}"
            )));
        }
        let key_bytes = &decoded[2..];
        if key_bytes.len() != 32 {
            return Err(SandboxError::InvalidDeclaration(format!(
                "did:key Ed25519 key is {} bytes, expected 32",
                key_bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        Ok(key)
    } else {
        Err(SandboxError::InvalidDeclaration(format!(
            "unsupported DID format for key extraction: {did_str}"
        )))
    }
}

// ---------------------------------------------------------------------------
// Helper: sign a declaration
// ---------------------------------------------------------------------------

/// Signs a capability declaration with the given Ed25519 signing key.
///
/// Computes the canonical bytes (JCS without signature field), signs them,
/// and sets the `signature` field on the declaration.
///
/// # Errors
///
/// Returns `SandboxError::SerializationFailed` if canonical serialization fails.
pub fn sign_declaration(
    declaration: &mut CapabilityDeclaration,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), SandboxError> {
    use ed25519_dalek::Signer;

    // Temporarily clear signature for canonical computation.
    declaration.signature = Vec::new();
    let canonical = declaration.canonical_bytes()?;

    let signature = signing_key.sign(&canonical);
    declaration.signature = signature.to_bytes().to_vec();

    Ok(())
}

/// Computes the content hash of a capability declaration for integrity checks.
///
/// Uses SHA-256 over the canonical JSON bytes (excluding signature).
///
/// # Errors
///
/// Returns `SandboxError::SerializationFailed` if canonical serialization fails.
pub fn declaration_content_hash(
    declaration: &CapabilityDeclaration,
) -> Result<[u8; 32], SandboxError> {
    let canonical = declaration.canonical_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_clone,
    clippy::large_stack_frames
)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use scp_protocol::context::ContextParams;

    /// Creates a test signing key and its corresponding did:key DID.
    fn test_keypair() -> (SigningKey, DID) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();

        // Encode as did:key with Ed25519 multicodec prefix.
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(&pubkey_bytes);
        let encoded = bs58::encode(&prefixed).into_string();
        let did = DID::from(format!("did:key:z{encoded}"));

        (signing_key, did)
    }

    /// Creates a minimal valid capability declaration (unsigned).
    fn test_declaration(app_did: &DID) -> CapabilityDeclaration {
        CapabilityDeclaration {
            scp_version: "1.0".to_owned(),
            app_id: app_did.clone(),
            app_name: "Test App".to_owned(),
            app_version: "1.0.0".to_owned(),
            capabilities: vec![CapabilityEntry {
                resource: "scp:ctx:test/messaging".to_owned(),
                actions: vec!["read".to_owned(), "write".to_owned()],
                constraints: None,
            }],
            min_role: "member".to_owned(),
            signature: Vec::new(),
        }
    }

    /// Creates a signed test declaration.
    fn signed_test_declaration(signing_key: &SigningKey, app_did: &DID) -> CapabilityDeclaration {
        let mut decl = test_declaration(app_did);
        sign_declaration(&mut decl, signing_key).unwrap();
        decl
    }

    // -----------------------------------------------------------------------
    // Serialization / Deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn declaration_serialization_roundtrip() {
        let (signing_key, did) = test_keypair();
        let decl = signed_test_declaration(&signing_key, &did);

        let json = serde_json::to_string(&decl).unwrap();
        let roundtripped: CapabilityDeclaration = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtripped.scp_version, decl.scp_version);
        assert_eq!(roundtripped.app_id, decl.app_id);
        assert_eq!(roundtripped.app_name, decl.app_name);
        assert_eq!(roundtripped.app_version, decl.app_version);
        assert_eq!(roundtripped.capabilities, decl.capabilities);
        assert_eq!(roundtripped.min_role, decl.min_role);
        assert_eq!(roundtripped.signature, decl.signature);
    }

    #[test]
    fn declaration_deserialization_from_json_string() {
        let (signing_key, did) = test_keypair();
        let decl = signed_test_declaration(&signing_key, &did);
        let json = serde_json::to_string_pretty(&decl).unwrap();

        let parsed: CapabilityDeclaration = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.app_id, did);
    }

    #[test]
    fn declaration_serialization_includes_all_fields() {
        let (signing_key, did) = test_keypair();
        let decl = signed_test_declaration(&signing_key, &did);
        let value: serde_json::Value = serde_json::to_value(&decl).unwrap();

        assert!(value.get("scp_version").is_some());
        assert!(value.get("app_id").is_some());
        assert!(value.get("app_name").is_some());
        assert!(value.get("app_version").is_some());
        assert!(value.get("capabilities").is_some());
        assert!(value.get("min_role").is_some());
        assert!(value.get("signature").is_some());
    }

    #[test]
    fn declaration_canonical_bytes_exclude_signature() {
        let (_, did) = test_keypair();
        let decl = test_declaration(&did);
        let canonical = decl.canonical_bytes().unwrap();
        let canonical_str = String::from_utf8(canonical).unwrap();

        assert!(!canonical_str.contains("signature"));
    }

    #[test]
    fn declaration_canonical_bytes_deterministic() {
        let (_, did) = test_keypair();
        let decl = test_declaration(&did);

        let bytes1 = decl.canonical_bytes().unwrap();
        let bytes2 = decl.canonical_bytes().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    // -----------------------------------------------------------------------
    // Signature Verification
    // -----------------------------------------------------------------------

    #[test]
    fn signature_verification_valid() {
        let (signing_key, did) = test_keypair();
        let decl = signed_test_declaration(&signing_key, &did);

        assert!(decl.verify().is_ok());
    }

    #[test]
    fn signature_verification_invalid_signature() {
        let (signing_key, did) = test_keypair();
        let mut decl = signed_test_declaration(&signing_key, &did);

        // Tamper with the signature.
        if let Some(byte) = decl.signature.get_mut(0) {
            *byte ^= 0xff;
        }

        assert!(matches!(
            decl.verify(),
            Err(SandboxError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn signature_verification_wrong_key() {
        let (signing_key, did) = test_keypair();
        let mut decl = signed_test_declaration(&signing_key, &did);

        // Replace app_id with a different DID (signature won't match).
        let (_, other_did) = test_keypair();
        decl.app_id = other_did;

        assert!(matches!(
            decl.verify(),
            Err(SandboxError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn signature_verification_empty_signature() {
        let (_, did) = test_keypair();
        let decl = test_declaration(&did);

        assert!(matches!(
            decl.verify(),
            Err(SandboxError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn signature_verification_truncated_signature() {
        let (signing_key, did) = test_keypair();
        let mut decl = signed_test_declaration(&signing_key, &did);

        decl.signature.truncate(32); // Half the Ed25519 signature.

        assert!(matches!(
            decl.verify(),
            Err(SandboxError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn signature_verification_after_content_change() {
        let (signing_key, did) = test_keypair();
        let mut decl = signed_test_declaration(&signing_key, &did);

        // Modify content after signing.
        decl.app_name = "Tampered App".to_owned();

        assert!(matches!(
            decl.verify(),
            Err(SandboxError::SignatureVerificationFailed)
        ));
    }

    // -----------------------------------------------------------------------
    // Structural Validation
    // -----------------------------------------------------------------------

    #[test]
    fn validate_structure_valid_declaration() {
        let (_, did) = test_keypair();
        let decl = test_declaration(&did);
        assert!(decl.validate_structure().is_ok());
    }

    #[test]
    fn validate_structure_empty_app_name() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.app_name = String::new();

        assert!(matches!(
            decl.validate_structure(),
            Err(SandboxError::InvalidDeclaration(msg)) if msg.contains("app_name")
        ));
    }

    #[test]
    fn validate_structure_app_name_too_long() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.app_name = "a".repeat(MAX_APP_NAME_BYTES + 1);

        assert!(matches!(
            decl.validate_structure(),
            Err(SandboxError::InvalidDeclaration(msg)) if msg.contains("128")
        ));
    }

    #[test]
    fn validate_structure_empty_capabilities() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.capabilities = vec![];

        assert!(matches!(
            decl.validate_structure(),
            Err(SandboxError::InvalidDeclaration(msg)) if msg.contains("at least 1")
        ));
    }

    #[test]
    fn validate_structure_too_many_capabilities() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.capabilities = (0..65)
            .map(|i| CapabilityEntry {
                resource: format!("scp:ctx:test/custom_{i}"),
                actions: vec!["read".to_owned()],
                constraints: None,
            })
            .collect();

        assert!(matches!(
            decl.validate_structure(),
            Err(SandboxError::InvalidDeclaration(msg)) if msg.contains("64")
        ));
    }

    #[test]
    fn validate_structure_empty_actions() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.capabilities[0].actions = vec![];

        assert!(matches!(
            decl.validate_structure(),
            Err(SandboxError::InvalidDeclaration(msg)) if msg.contains("action")
        ));
    }

    #[test]
    fn validate_structure_incompatible_version() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.scp_version = "2.0".to_owned();

        assert!(matches!(
            decl.validate_structure(),
            Err(SandboxError::InvalidDeclaration(msg)) if msg.contains("incompatible")
        ));
    }

    #[test]
    fn validate_structure_empty_min_role() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.min_role = String::new();

        assert!(matches!(
            decl.validate_structure(),
            Err(SandboxError::InvalidDeclaration(msg)) if msg.contains("min_role")
        ));
    }

    // -----------------------------------------------------------------------
    // Ceiling Validation
    // -----------------------------------------------------------------------

    #[test]
    fn ceiling_validation_pass() {
        let (signing_key, did) = test_keypair();
        let decl = signed_test_declaration(&signing_key, &did);

        let ceiling = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let role_caps = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        let result = validate_declaration(&decl, &ceiling, &role_caps, handle);
        assert!(result.is_ok());
    }

    #[test]
    fn ceiling_validation_fail_not_in_ceiling() {
        let (signing_key, did) = test_keypair();
        let decl = signed_test_declaration(&signing_key, &did);

        // Only MessagesRead in ceiling — MessagesWrite is missing.
        let ceiling = vec![Capability::MessagesRead];
        let role_caps = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        let result = validate_declaration(&decl, &ceiling, &role_caps, handle);
        assert!(matches!(result, Err(SandboxError::CeilingExceeded { .. })));
    }

    #[test]
    fn ceiling_validation_fail_not_in_role() {
        let (signing_key, did) = test_keypair();
        let decl = signed_test_declaration(&signing_key, &did);

        let ceiling = vec![Capability::MessagesRead, Capability::MessagesWrite];
        // Only MessagesRead in role — MessagesWrite is missing.
        let role_caps = vec![Capability::MessagesRead];
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        let result = validate_declaration(&decl, &ceiling, &role_caps, handle);
        assert!(matches!(result, Err(SandboxError::CeilingExceeded { .. })));
    }

    #[test]
    fn ceiling_validation_all_or_nothing() {
        let (signing_key, did) = test_keypair();
        let mut decl = CapabilityDeclaration {
            scp_version: "1.0".to_owned(),
            app_id: did.clone(),
            app_name: "Multi Cap App".to_owned(),
            app_version: "1.0.0".to_owned(),
            capabilities: vec![
                CapabilityEntry {
                    resource: "scp:ctx:test/messaging".to_owned(),
                    actions: vec!["read".to_owned()],
                    constraints: None,
                },
                CapabilityEntry {
                    resource: "scp:ctx:test/governance".to_owned(),
                    actions: vec!["write".to_owned()],
                    constraints: None,
                },
            ],
            min_role: "member".to_owned(),
            signature: Vec::new(),
        };
        sign_declaration(&mut decl, &signing_key).unwrap();

        // Ceiling has MessagesRead but not GovernancePropose.
        let ceiling = vec![Capability::MessagesRead];
        let role_caps = vec![Capability::MessagesRead, Capability::GovernancePropose];
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        let result = validate_declaration(&decl, &ceiling, &role_caps, handle);
        // Should fail even though MessagesRead is valid.
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Role Capability Intersection
    // -----------------------------------------------------------------------

    #[test]
    fn role_intersection_admin_grants_all() {
        let (signing_key, did) = test_keypair();
        let mut decl = CapabilityDeclaration {
            scp_version: "1.0".to_owned(),
            app_id: did.clone(),
            app_name: "Admin App".to_owned(),
            app_version: "1.0.0".to_owned(),
            capabilities: vec![
                CapabilityEntry {
                    resource: "scp:ctx:test/messaging".to_owned(),
                    actions: vec!["read".to_owned(), "write".to_owned()],
                    constraints: None,
                },
                CapabilityEntry {
                    resource: "scp:ctx:test/governance".to_owned(),
                    actions: vec!["write".to_owned()],
                    constraints: None,
                },
            ],
            min_role: "admin".to_owned(),
            signature: Vec::new(),
        };
        sign_declaration(&mut decl, &signing_key).unwrap();

        // Admin has all capabilities.
        let ceiling = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::GovernancePropose,
        ];
        let role_caps = ceiling.clone();
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        let result = validate_declaration(&decl, &ceiling, &role_caps, handle);
        assert!(result.is_ok());
    }

    #[test]
    fn role_intersection_observer_read_only() {
        let (signing_key, did) = test_keypair();
        let mut decl = CapabilityDeclaration {
            scp_version: "1.0".to_owned(),
            app_id: did.clone(),
            app_name: "Read Only App".to_owned(),
            app_version: "1.0.0".to_owned(),
            capabilities: vec![CapabilityEntry {
                resource: "scp:ctx:test/messaging".to_owned(),
                actions: vec!["read".to_owned()],
                constraints: None,
            }],
            min_role: "observer".to_owned(),
            signature: Vec::new(),
        };
        sign_declaration(&mut decl, &signing_key).unwrap();

        let ceiling = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let role_caps = vec![Capability::MessagesRead]; // observer
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        let result = validate_declaration(&decl, &ceiling, &role_caps, handle);
        assert!(result.is_ok());

        let scoped = result.unwrap();
        assert!(scoped.has_capability(&Capability::MessagesRead));
        assert!(!scoped.has_capability(&Capability::MessagesWrite));
    }

    // -----------------------------------------------------------------------
    // ScopedHandle Enforcement
    // -----------------------------------------------------------------------

    fn make_scoped_handle(caps: Vec<Capability>) -> ScopedHandle {
        let (_, did) = test_keypair();
        let handle = ContextHandle::new("ctx-test".to_owned(), ContextParams::default());
        ScopedHandle::new(
            handle,
            caps.into_iter().collect(),
            did.clone(),
            test_declaration(&did),
        )
    }

    #[test]
    fn scoped_handle_check_messages_read_granted() {
        let handle = make_scoped_handle(vec![Capability::MessagesRead]);
        assert!(handle.check_read_messages().is_ok());
    }

    #[test]
    fn scoped_handle_check_messages_read_denied() {
        let handle = make_scoped_handle(vec![Capability::MessagesWrite]);
        assert!(matches!(
            handle.check_read_messages(),
            Err(SandboxError::CapabilityDenied { .. })
        ));
    }

    #[test]
    fn scoped_handle_check_messages_write_granted() {
        let handle = make_scoped_handle(vec![Capability::MessagesWrite]);
        assert!(handle.check_send_message().is_ok());
    }

    #[test]
    fn scoped_handle_check_messages_write_denied() {
        let handle = make_scoped_handle(vec![Capability::MessagesRead]);
        assert!(matches!(
            handle.check_send_message(),
            Err(SandboxError::CapabilityDenied { .. })
        ));
    }

    #[test]
    fn scoped_handle_check_governance_propose_granted() {
        let handle = make_scoped_handle(vec![Capability::GovernancePropose]);
        assert!(handle.check_propose_governance_action().is_ok());
    }

    #[test]
    fn scoped_handle_check_governance_propose_denied() {
        let handle = make_scoped_handle(vec![Capability::MessagesRead]);
        assert!(matches!(
            handle.check_propose_governance_action(),
            Err(SandboxError::CapabilityDenied { .. })
        ));
    }

    #[test]
    fn scoped_handle_check_governance_vote_granted() {
        let handle = make_scoped_handle(vec![Capability::GovernanceVote]);
        assert!(handle.check_governance_vote().is_ok());
    }

    #[test]
    fn scoped_handle_check_governance_vote_denied() {
        let handle = make_scoped_handle(vec![]);
        assert!(matches!(
            handle.check_governance_vote(),
            Err(SandboxError::CapabilityDenied { .. })
        ));
    }

    #[test]
    fn scoped_handle_check_tool_invoke_specific_granted() {
        let handle = make_scoped_handle(vec![Capability::OutletCall("my_tool".to_owned())]);
        assert!(handle.check_outlet_invoke("my_tool").is_ok());
    }

    #[test]
    fn scoped_handle_check_tool_invoke_specific_denied() {
        let handle = make_scoped_handle(vec![Capability::OutletCall("my_tool".to_owned())]);
        assert!(matches!(
            handle.check_outlet_invoke("other_tool"),
            Err(SandboxError::CapabilityDenied { .. })
        ));
    }

    #[test]
    fn scoped_handle_check_tool_invoke_all_covers_specific() {
        let handle = make_scoped_handle(vec![Capability::OutletCallAll]);
        assert!(handle.check_outlet_invoke("any_tool").is_ok());
    }

    #[test]
    fn scoped_handle_check_tool_register_granted() {
        let handle = make_scoped_handle(vec![Capability::OutletRegister]);
        assert!(handle.check_outlet_register().is_ok());
    }

    #[test]
    fn scoped_handle_check_tool_register_denied() {
        let handle = make_scoped_handle(vec![]);
        assert!(matches!(
            handle.check_outlet_register(),
            Err(SandboxError::CapabilityDenied { .. })
        ));
    }

    #[test]
    fn scoped_handle_check_member_invite_granted() {
        let handle = make_scoped_handle(vec![Capability::MemberInvite]);
        assert!(handle.check_member_invite().is_ok());
    }

    #[test]
    fn scoped_handle_check_member_invite_denied() {
        let handle = make_scoped_handle(vec![]);
        assert!(matches!(
            handle.check_member_invite(),
            Err(SandboxError::CapabilityDenied { .. })
        ));
    }

    #[test]
    fn scoped_handle_check_member_remove_granted() {
        let handle = make_scoped_handle(vec![Capability::MemberRemove]);
        assert!(handle.check_member_remove().is_ok());
    }

    #[test]
    fn scoped_handle_check_member_remove_denied() {
        let handle = make_scoped_handle(vec![]);
        assert!(matches!(
            handle.check_member_remove(),
            Err(SandboxError::CapabilityDenied { .. })
        ));
    }

    #[test]
    fn scoped_handle_check_role_assign_granted() {
        let handle = make_scoped_handle(vec![Capability::RoleAssign]);
        assert!(handle.check_role_assign().is_ok());
    }

    #[test]
    fn scoped_handle_check_context_close_granted() {
        let handle = make_scoped_handle(vec![Capability::ContextClose]);
        assert!(handle.check_context_close().is_ok());
    }

    #[test]
    fn scoped_handle_check_context_close_denied() {
        let handle = make_scoped_handle(vec![]);
        assert!(matches!(
            handle.check_context_close(),
            Err(SandboxError::CapabilityDenied { .. })
        ));
    }

    #[test]
    fn scoped_handle_check_bridging_granted() {
        let handle = make_scoped_handle(vec![Capability::Bridging]);
        assert!(handle.check_bridging().is_ok());
    }

    #[test]
    fn scoped_handle_check_metadata_edit_granted() {
        let handle = make_scoped_handle(vec![Capability::MetadataEdit]);
        assert!(handle.check_metadata_edit().is_ok());
    }

    #[test]
    fn scoped_handle_check_member_ban_granted() {
        let handle = make_scoped_handle(vec![Capability::MemberBan]);
        assert!(handle.check_member_ban().is_ok());
    }

    #[test]
    fn scoped_handle_check_child_context_create_granted() {
        let handle = make_scoped_handle(vec![Capability::ChildContextCreate]);
        assert!(handle.check_child_context_create().is_ok());
    }

    #[test]
    fn scoped_handle_check_media_voice_granted() {
        let handle = make_scoped_handle(vec![Capability::MediaVoice]);
        assert!(handle.check_media_voice().is_ok());
    }

    #[test]
    fn scoped_handle_check_media_video_granted() {
        let handle = make_scoped_handle(vec![Capability::MediaVideo]);
        assert!(handle.check_media_video().is_ok());
    }

    #[test]
    fn scoped_handle_check_media_screen_share_granted() {
        let handle = make_scoped_handle(vec![Capability::MediaScreenShare]);
        assert!(handle.check_media_screen_share().is_ok());
    }

    #[test]
    fn scoped_handle_check_tool_interface_granted() {
        let handle = make_scoped_handle(vec![Capability::OutletInterface]);
        assert!(handle.check_outlet_interface().is_ok());
    }

    // -----------------------------------------------------------------------
    // No Escalation Guarantee
    // -----------------------------------------------------------------------

    #[test]
    fn no_escalation_scoped_handle_cannot_gain_capabilities() {
        let handle = make_scoped_handle(vec![Capability::MessagesRead]);

        // Scoped handle only has MessagesRead.
        assert!(handle.check_read_messages().is_ok());

        // All other capabilities should be denied.
        assert!(handle.check_send_message().is_err());
        assert!(handle.check_propose_governance_action().is_err());
        assert!(handle.check_governance_vote().is_err());
        assert!(handle.check_outlet_invoke("any").is_err());
        assert!(handle.check_outlet_register().is_err());
        assert!(handle.check_member_invite().is_err());
        assert!(handle.check_member_remove().is_err());
        assert!(handle.check_role_assign().is_err());
        assert!(handle.check_context_close().is_err());
        assert!(handle.check_bridging().is_err());
        assert!(handle.check_metadata_edit().is_err());
        assert!(handle.check_member_ban().is_err());
        assert!(handle.check_child_context_create().is_err());
        assert!(handle.check_media_voice().is_err());
        assert!(handle.check_media_video().is_err());
        assert!(handle.check_media_screen_share().is_err());
        assert!(handle.check_outlet_interface().is_err());
    }

    #[test]
    fn no_escalation_empty_capabilities() {
        let handle = make_scoped_handle(vec![]);

        // All capabilities should be denied.
        assert!(handle.check_read_messages().is_err());
        assert!(handle.check_send_message().is_err());
        assert!(handle.check_propose_governance_action().is_err());
        assert!(handle.check_governance_vote().is_err());
    }

    // -----------------------------------------------------------------------
    // Event Log Recording
    // -----------------------------------------------------------------------

    #[test]
    fn format_bind_event_produces_parseable_string() {
        let event = AppBindEvent {
            app_did: DID::from("did:key:z1234"),
            capabilities: vec![Capability::MessagesRead, Capability::MessagesWrite],
            app_name: "Test App".to_owned(),
            app_version: "1.0.0".to_owned(),
        };

        let formatted = format_bind_event(&event);
        assert!(formatted.starts_with("AppBound:"));
        assert!(formatted.contains("did:key:z1234"));
        assert!(formatted.contains("messages:read"));
        assert!(formatted.contains("messages:write"));
    }

    #[test]
    fn format_unbind_event_produces_parseable_string() {
        let event = AppUnbindEvent {
            app_did: DID::from("did:key:z1234"),
        };

        let formatted = format_unbind_event(&event);
        assert_eq!(formatted, "AppUnbound:did:key:z1234");
    }

    // -----------------------------------------------------------------------
    // Capability Entry Parsing
    // -----------------------------------------------------------------------

    #[test]
    fn capability_entry_messaging_read() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/messaging".to_owned(),
            actions: vec!["read".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert_eq!(caps, vec![Capability::MessagesRead]);
    }

    #[test]
    fn capability_entry_messaging_write() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/messaging".to_owned(),
            actions: vec!["write".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert_eq!(caps, vec![Capability::MessagesWrite]);
    }

    #[test]
    fn capability_entry_messaging_read_write() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/messaging".to_owned(),
            actions: vec!["read".to_owned(), "write".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert!(caps.contains(&Capability::MessagesRead));
        assert!(caps.contains(&Capability::MessagesWrite));
    }

    #[test]
    fn capability_entry_tools_invoke() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/tools".to_owned(),
            actions: vec!["invoke".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert_eq!(caps, vec![Capability::OutletCallAll]);
    }

    #[test]
    fn capability_entry_specific_tool() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/tools/my_tool".to_owned(),
            actions: vec!["invoke".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert_eq!(caps, vec![Capability::OutletCall("my_tool".to_owned())]);
    }

    #[test]
    fn capability_entry_governance() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/governance".to_owned(),
            actions: vec!["admin".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert!(caps.contains(&Capability::GovernancePropose));
        assert!(caps.contains(&Capability::GovernanceVote));
    }

    #[test]
    fn capability_entry_with_constraints() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/messaging".to_owned(),
            actions: vec!["read".to_owned()],
            constraints: Some(CapabilityConstraint {
                max_message_size: Some(65536),
                max_invocations_per_minute: None,
                media_types: Some(vec!["text/plain".to_owned()]),
            }),
        };
        let caps = entry.to_capabilities();
        assert_eq!(caps, vec![Capability::MessagesRead]);
    }

    // -----------------------------------------------------------------------
    // Full Validation Flow
    // -----------------------------------------------------------------------

    #[test]
    fn full_validation_happy_path() {
        let (signing_key, did) = test_keypair();
        let decl = signed_test_declaration(&signing_key, &did);

        let ceiling = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let role_caps = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        let scoped = validate_declaration(&decl, &ceiling, &role_caps, handle).unwrap();

        assert_eq!(scoped.context_id(), "ctx-1");
        assert_eq!(scoped.app_did(), &did);
        assert!(scoped.has_capability(&Capability::MessagesRead));
        assert!(scoped.has_capability(&Capability::MessagesWrite));
    }

    #[test]
    fn full_validation_rejects_invalid_structure() {
        let (signing_key, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.capabilities = vec![]; // Invalid: empty.
        sign_declaration(&mut decl, &signing_key).unwrap();

        let ceiling = vec![Capability::MessagesRead];
        let role_caps = vec![Capability::MessagesRead];
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        let result = validate_declaration(&decl, &ceiling, &role_caps, handle);
        assert!(matches!(result, Err(SandboxError::InvalidDeclaration(_))));
    }

    #[test]
    fn full_validation_rejects_invalid_signature() {
        let (signing_key, did) = test_keypair();
        let mut decl = signed_test_declaration(&signing_key, &did);
        decl.signature[0] ^= 0xff; // Tamper.

        let ceiling = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let role_caps = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        let result = validate_declaration(&decl, &ceiling, &role_caps, handle);
        assert!(matches!(
            result,
            Err(SandboxError::SignatureVerificationFailed)
        ));
    }

    // -----------------------------------------------------------------------
    // Content Hash
    // -----------------------------------------------------------------------

    #[test]
    fn declaration_content_hash_deterministic() {
        let (_, did) = test_keypair();
        let decl = test_declaration(&did);

        let hash1 = declaration_content_hash(&decl).unwrap();
        let hash2 = declaration_content_hash(&decl).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn declaration_content_hash_changes_with_content() {
        let (_, did) = test_keypair();
        let decl1 = test_declaration(&did);

        let mut decl2 = test_declaration(&did);
        decl2.app_name = "Different App".to_owned();

        let hash1 = declaration_content_hash(&decl1).unwrap();
        let hash2 = declaration_content_hash(&decl2).unwrap();
        assert_ne!(hash1, hash2);
    }

    // -----------------------------------------------------------------------
    // ToolInvokeAll covers ToolInvoke in ceiling/role validation
    // -----------------------------------------------------------------------

    #[test]
    fn tool_invoke_all_covers_specific_tool_in_ceiling() {
        let (signing_key, did) = test_keypair();
        let mut decl = CapabilityDeclaration {
            scp_version: "1.0".to_owned(),
            app_id: did.clone(),
            app_name: "Tool App".to_owned(),
            app_version: "1.0.0".to_owned(),
            capabilities: vec![CapabilityEntry {
                resource: "scp:ctx:test/tools/specific_tool".to_owned(),
                actions: vec!["invoke".to_owned()],
                constraints: None,
            }],
            min_role: "member".to_owned(),
            signature: Vec::new(),
        };
        sign_declaration(&mut decl, &signing_key).unwrap();

        // Ceiling has ToolInvokeAll, not the specific tool.
        let ceiling = vec![Capability::OutletCallAll];
        let role_caps = vec![Capability::OutletCallAll];
        let handle = ContextHandle::new("ctx-1".to_owned(), ContextParams::default());

        let result = validate_declaration(&decl, &ceiling, &role_caps, handle);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // ScopedHandle Properties
    // -----------------------------------------------------------------------

    #[test]
    fn scoped_handle_context_id() {
        let handle = make_scoped_handle(vec![Capability::MessagesRead]);
        assert_eq!(handle.context_id(), "ctx-test");
    }

    #[test]
    fn scoped_handle_app_did() {
        let (_, did) = test_keypair();
        let handle = ContextHandle::new("ctx-test".to_owned(), ContextParams::default());
        let scoped = ScopedHandle::new(handle, HashSet::new(), did.clone(), test_declaration(&did));
        assert_eq!(scoped.app_did(), &did);
    }

    #[test]
    fn scoped_handle_allowed_capabilities() {
        let caps = vec![Capability::MessagesRead, Capability::MessagesWrite];
        let handle = make_scoped_handle(caps.clone());
        let allowed = handle.allowed_capabilities();
        assert_eq!(allowed.len(), 2);
        assert!(allowed.contains(&Capability::MessagesRead));
        assert!(allowed.contains(&Capability::MessagesWrite));
    }

    #[test]
    fn scoped_handle_has_capability() {
        let handle = make_scoped_handle(vec![Capability::MessagesRead]);
        assert!(handle.has_capability(&Capability::MessagesRead));
        assert!(!handle.has_capability(&Capability::MessagesWrite));
    }

    #[test]
    fn scoped_handle_declaration() {
        let (_, did) = test_keypair();
        let decl = test_declaration(&did);
        let handle = ContextHandle::new("ctx-test".to_owned(), ContextParams::default());
        let scoped = ScopedHandle::new(handle, HashSet::new(), did, decl.clone());
        assert_eq!(scoped.declaration().app_name, decl.app_name);
    }

    // -----------------------------------------------------------------------
    // SandboxError Display
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_error_display() {
        let err = SandboxError::CapabilityDenied {
            required: Capability::MessagesWrite,
            app_did: DID::from("did:key:test"),
        };
        assert!(err.to_string().contains("messages:write"));
        assert!(err.to_string().contains("did:key:test"));

        let err = SandboxError::InvalidDeclaration("bad field".to_owned());
        assert!(err.to_string().contains("bad field"));

        let err = SandboxError::SignatureVerificationFailed;
        assert!(err.to_string().contains("signature"));

        let err = SandboxError::CeilingExceeded {
            denied_capabilities: vec![DeniedCapability {
                capability: Capability::Bridging,
                reason: DenialReason::NotInCeiling,
            }],
        };
        assert!(err.to_string().contains("bridging"));
    }

    // -----------------------------------------------------------------------
    // DeniedCapability / DenialReason
    // -----------------------------------------------------------------------

    #[test]
    fn denial_reason_display() {
        assert_eq!(
            DenialReason::NotInCeiling.to_string(),
            "not in context ceiling"
        );
        assert_eq!(
            DenialReason::NotInRole.to_string(),
            "not granted by agent role"
        );
    }

    // -----------------------------------------------------------------------
    // Constraint Serialization
    // -----------------------------------------------------------------------

    #[test]
    fn constraint_serialization_roundtrip() {
        let constraint = CapabilityConstraint {
            max_message_size: Some(65536),
            max_invocations_per_minute: Some(60),
            media_types: Some(vec!["text/plain".to_owned(), "application/json".to_owned()]),
        };

        let json = serde_json::to_string(&constraint).unwrap();
        let roundtripped: CapabilityConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped, constraint);
    }

    #[test]
    fn constraint_serialization_omits_none() {
        let constraint = CapabilityConstraint {
            max_message_size: None,
            max_invocations_per_minute: None,
            media_types: None,
        };

        let json = serde_json::to_string(&constraint).unwrap();
        assert_eq!(json, "{}");
    }

    // -----------------------------------------------------------------------
    // App Bind/Unbind Event Serialization
    // -----------------------------------------------------------------------

    #[test]
    fn app_bind_event_serialization() {
        let event = AppBindEvent {
            app_did: DID::from("did:key:z1234"),
            capabilities: vec![Capability::MessagesRead],
            app_name: "My App".to_owned(),
            app_version: "1.0.0".to_owned(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let roundtripped: AppBindEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped, event);
    }

    #[test]
    fn app_unbind_event_serialization() {
        let event = AppUnbindEvent {
            app_did: DID::from("did:key:z1234"),
        };

        let json = serde_json::to_string(&event).unwrap();
        let roundtripped: AppUnbindEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped, event);
    }

    // -----------------------------------------------------------------------
    // sign_declaration
    // -----------------------------------------------------------------------

    #[test]
    fn sign_declaration_produces_valid_signature() {
        let (signing_key, did) = test_keypair();
        let mut decl = test_declaration(&did);
        sign_declaration(&mut decl, &signing_key).unwrap();

        assert_eq!(decl.signature.len(), 64);
        assert!(decl.verify().is_ok());
    }

    #[test]
    fn sign_declaration_idempotent_canonical_bytes() {
        let (signing_key, did) = test_keypair();

        let mut decl1 = test_declaration(&did);
        sign_declaration(&mut decl1, &signing_key).unwrap();

        let mut decl2 = test_declaration(&did);
        sign_declaration(&mut decl2, &signing_key).unwrap();

        // Signatures should be identical for the same content.
        // (Ed25519 is deterministic per RFC 8032.)
        assert_eq!(decl1.signature, decl2.signature);
    }

    // -----------------------------------------------------------------------
    // DID Key Extraction
    // -----------------------------------------------------------------------

    #[test]
    fn extract_pubkey_from_did_key() {
        let (_, did) = test_keypair();
        let result = extract_ed25519_pubkey_from_did(&did);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn extract_pubkey_unsupported_did() {
        let did = DID::from("did:web:example.com");
        let result = extract_ed25519_pubkey_from_did(&did);
        assert!(matches!(result, Err(SandboxError::InvalidDeclaration(_))));
    }

    #[test]
    fn extract_pubkey_from_canonical_did_dht() {
        // Regression: the inline decoder stripped only "did:dht:" (not the
        // multibase 'z'), so the 'z' stayed in the z-base-32 payload → 33 bytes
        // → it rejected EVERY valid did:dht DID. Delegation to the hardened
        // scp-did parser fixes the prefix handling: a canonical did:dht:z DID
        // now resolves to the correct 32-byte Ed25519 key.
        let pubkey_bytes: [u8; 32] = [0x37; 32];
        let did = DID::from(format!("did:dht:z{}", zbase32::encode(&pubkey_bytes)));

        let result = extract_ed25519_pubkey_from_did(&did)
            .expect("a canonical did:dht DID must resolve to its Ed25519 key");
        assert_eq!(
            result, pubkey_bytes,
            "extracted key must equal the encoded public key"
        );
    }

    #[test]
    fn extract_pubkey_rejects_non_canonical_did_dht() {
        // The delegated scp-did parser enforces z-base-32 canonicality: a
        // non-canonical spelling of a valid key (differing only in the
        // trailing padding bits) MUST be rejected, so two DID strings can never
        // resolve to the same app-declaration signing key.
        const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

        let pubkey_bytes: [u8; 32] = [0x37; 32];
        let canonical_encoded = zbase32::encode(&pubkey_bytes);

        // Build a non-canonical alternate by toggling a padding bit of the
        // trailing char.
        let last_char = canonical_encoded.as_bytes()[canonical_encoded.len() - 1];
        let last_idx = ALPHABET
            .iter()
            .position(|&c| c == last_char)
            .expect("canonical char must be in alphabet");
        let mut mutated_bytes = canonical_encoded.as_bytes().to_vec();
        let last_pos = mutated_bytes.len() - 1;
        mutated_bytes[last_pos] = ALPHABET[last_idx ^ 1];
        let mutated_encoded =
            String::from_utf8(mutated_bytes).expect("z-base-32 alphabet is ASCII");

        // Sanity: the mutated spelling still decodes to the same 32 bytes.
        assert_eq!(
            zbase32::decode(&mutated_encoded)
                .expect("alternate decodes")
                .as_slice(),
            &pubkey_bytes[..],
            "the mutated spelling must be a real non-canonical alternate of the same key"
        );

        let did = DID::from(format!("did:dht:z{mutated_encoded}"));
        let result = extract_ed25519_pubkey_from_did(&did);
        assert!(
            matches!(result, Err(SandboxError::InvalidDeclaration(_))),
            "non-canonical did:dht spelling must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // CapabilityConstraint edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn capability_entry_members_read() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/members".to_owned(),
            actions: vec!["read".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert!(caps.contains(&Capability::MessagesRead));
    }

    #[test]
    fn capability_entry_roles_admin() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/roles".to_owned(),
            actions: vec!["admin".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert!(caps.contains(&Capability::RoleAssign));
    }

    #[test]
    fn capability_entry_context_admin() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/context".to_owned(),
            actions: vec!["admin".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert!(caps.contains(&Capability::ContextClose));
    }

    #[test]
    fn capability_entry_metadata_write() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/metadata".to_owned(),
            actions: vec!["write".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert!(caps.contains(&Capability::MetadataEdit));
    }

    #[test]
    fn capability_entry_custom_unknown() {
        let entry = CapabilityEntry {
            resource: "scp:ctx:test/custom_thing".to_owned(),
            actions: vec!["special".to_owned()],
            constraints: None,
        };
        let caps = entry.to_capabilities();
        assert_eq!(
            caps,
            vec![Capability::Custom("custom_thing:special".to_owned())]
        );
    }

    // -----------------------------------------------------------------------
    // Max capabilities boundary
    // -----------------------------------------------------------------------

    #[test]
    fn validate_structure_exactly_64_capabilities() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.capabilities = (0..64)
            .map(|i| CapabilityEntry {
                resource: format!("scp:ctx:test/custom_{i}"),
                actions: vec!["read".to_owned()],
                constraints: None,
            })
            .collect();

        assert!(decl.validate_structure().is_ok());
    }

    #[test]
    fn validate_structure_exactly_128_byte_app_name() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.app_name = "a".repeat(128);

        assert!(decl.validate_structure().is_ok());
    }

    // -----------------------------------------------------------------------
    // Additional edge cases to reach 100+ tests
    // -----------------------------------------------------------------------

    #[test]
    fn scoped_handle_empty_capabilities_denies_all() {
        let handle = make_scoped_handle(vec![]);
        assert!(!handle.has_capability(&Capability::MessagesRead));
        assert!(!handle.has_capability(&Capability::MessagesWrite));
        assert!(!handle.has_capability(&Capability::GovernancePropose));
        assert!(!handle.has_capability(&Capability::OutletCallAll));
    }

    #[test]
    fn scoped_handle_custom_capability() {
        let handle = make_scoped_handle(vec![Capability::Custom("my:custom".to_owned())]);
        assert!(handle.has_capability(&Capability::Custom("my:custom".to_owned())));
        assert!(!handle.has_capability(&Capability::Custom("other:custom".to_owned())));
    }

    #[test]
    fn validate_structure_compatible_minor_version() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.scp_version = "1.5".to_owned(); // Same major, different minor.

        assert!(decl.validate_structure().is_ok());
    }

    #[test]
    fn requested_capabilities_returns_all() {
        let (_, did) = test_keypair();
        let mut decl = test_declaration(&did);
        decl.capabilities = vec![
            CapabilityEntry {
                resource: "scp:ctx:test/messaging".to_owned(),
                actions: vec!["read".to_owned()],
                constraints: None,
            },
            CapabilityEntry {
                resource: "scp:ctx:test/governance".to_owned(),
                actions: vec!["write".to_owned()],
                constraints: None,
            },
        ];

        let caps = decl.requested_capabilities();
        assert!(caps.contains(&Capability::MessagesRead));
        assert!(caps.contains(&Capability::GovernancePropose));
    }

    #[test]
    fn format_bind_event_empty_capabilities() {
        let event = AppBindEvent {
            app_did: DID::from("did:key:z1234"),
            capabilities: vec![],
            app_name: "Empty App".to_owned(),
            app_version: "0.0.1".to_owned(),
        };
        let formatted = format_bind_event(&event);
        assert!(formatted.contains("[]"));
    }

    #[test]
    fn scoped_handle_check_capability_error_includes_app_did() {
        let (_, did) = test_keypair();
        let handle = ContextHandle::new("ctx-test".to_owned(), ContextParams::default());
        let scoped = ScopedHandle::new(handle, HashSet::new(), did.clone(), test_declaration(&did));
        let err = scoped.check_capability(&Capability::MessagesRead);
        assert!(err.is_err());
        if let Err(SandboxError::CapabilityDenied { app_did, .. }) = err {
            assert_eq!(app_did, did);
        }
    }

    #[test]
    fn canonical_bytes_stable_across_signature_values() {
        let (signing_key, did) = test_keypair();
        let mut decl1 = test_declaration(&did);
        decl1.signature = vec![0u8; 64];
        let bytes1 = decl1.canonical_bytes().unwrap();

        let mut decl2 = test_declaration(&did);
        sign_declaration(&mut decl2, &signing_key).unwrap();
        let bytes2 = decl2.canonical_bytes().unwrap();

        // Canonical bytes exclude signature, so both should be identical.
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn declaration_with_multiple_constraints() {
        let (signing_key, did) = test_keypair();
        let mut decl = CapabilityDeclaration {
            scp_version: "1.0".to_owned(),
            app_id: did.clone(),
            app_name: "Constrained App".to_owned(),
            app_version: "2.0.0".to_owned(),
            capabilities: vec![
                CapabilityEntry {
                    resource: "scp:ctx:test/messaging".to_owned(),
                    actions: vec!["read".to_owned(), "write".to_owned()],
                    constraints: Some(CapabilityConstraint {
                        max_message_size: Some(65536),
                        max_invocations_per_minute: None,
                        media_types: Some(vec!["text/plain".to_owned()]),
                    }),
                },
                CapabilityEntry {
                    resource: "scp:ctx:test/tools/scheduler".to_owned(),
                    actions: vec!["invoke".to_owned()],
                    constraints: Some(CapabilityConstraint {
                        max_message_size: None,
                        max_invocations_per_minute: Some(60),
                        media_types: None,
                    }),
                },
            ],
            min_role: "member".to_owned(),
            signature: Vec::new(),
        };
        sign_declaration(&mut decl, &signing_key).unwrap();

        // Verify structurally valid.
        assert!(decl.validate_structure().is_ok());
        // Verify signature.
        assert!(decl.verify().is_ok());
        // Verify roundtrip.
        let json = serde_json::to_string(&decl).unwrap();
        let roundtripped: CapabilityDeclaration = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped, decl);
    }

    #[test]
    fn scoped_handle_multiple_capabilities() {
        let caps = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::GovernancePropose,
            Capability::OutletCallAll,
            Capability::MemberInvite,
        ];
        let handle = make_scoped_handle(caps);

        assert!(handle.check_read_messages().is_ok());
        assert!(handle.check_send_message().is_ok());
        assert!(handle.check_propose_governance_action().is_ok());
        assert!(handle.check_outlet_invoke("any_tool").is_ok());
        assert!(handle.check_member_invite().is_ok());
        // Not granted:
        assert!(handle.check_context_close().is_err());
        assert!(handle.check_member_remove().is_err());
    }
}
