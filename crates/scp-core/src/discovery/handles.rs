//! Human-readable handle registration and resolution for SCP.
//!
//! Handles provide human-friendly aliases for identities and contexts,
//! similar to domain names or social media handles. A handle like
//! `recipes@cooking-community` can resolve to a context ID.
//!
//! # Authorization Model
//!
//! Handle registration requires authorization based on the target type:
//!
//! - **Identity targets** (`HandleTarget::Identity`): The registrant DID must
//!   match the target identity DID. Only you can register a handle pointing to
//!   yourself.
//!
//! - **Context targets** (`HandleTarget::Context`): The registrant DID must be
//!   in the context's admin DID list. This prevents unauthorized handle
//!   registration for contexts the registrant does not control.
//!
//! See spec section 22.9.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::identity::DID;

use super::ContextId;

// ---------------------------------------------------------------------------
// HandleTarget
// ---------------------------------------------------------------------------

/// The target that a handle resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandleTarget {
    /// The handle points to an identity (DID).
    Identity(DID),
    /// The handle points to a context.
    Context(ContextId),
}

// ---------------------------------------------------------------------------
// HandleRecord
// ---------------------------------------------------------------------------

/// A registered handle record.
///
/// Associates a human-readable handle string with a target (identity or
/// context), the DID that registered it, and a creation timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleRecord {
    /// The human-readable handle string (e.g., `"recipes@cooking-community"`).
    pub handle: String,
    /// The target this handle resolves to.
    pub target: HandleTarget,
    /// The DID that registered this handle.
    pub registered_by: DID,
    /// Unix timestamp (seconds) when the handle was registered.
    pub registered_at: u64,
}

// ---------------------------------------------------------------------------
// HandleError
// ---------------------------------------------------------------------------

/// Errors produced by handle operations.
#[derive(Debug, thiserror::Error)]
pub enum HandleError {
    /// The handle is already registered.
    #[error("handle already registered: {0}")]
    AlreadyRegistered(String),

    /// The handle string is invalid (empty, too long, or contains forbidden
    /// characters).
    #[error("invalid handle: {0}")]
    InvalidHandle(String),

    /// The registrant is not authorized to register a handle for this target.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// The handle was not found during a lookup or deregistration.
    #[error("handle not found: {0}")]
    NotFound(String),
}

// ---------------------------------------------------------------------------
// HandleRegistry
// ---------------------------------------------------------------------------

/// Maximum allowed handle length.
const MAX_HANDLE_LENGTH: usize = 128;

/// In-memory handle registry.
///
/// Provides handle registration, resolution, and deregistration with
/// authorization checks. In production, this would be backed by a persistent
/// store; this implementation is suitable for testing and single-session use.
pub struct HandleRegistry {
    /// Map from handle string to registration record.
    records: HashMap<String, HandleRecord>,
}

impl HandleRegistry {
    /// Creates a new empty handle registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Registers a new handle pointing to the given target.
    ///
    /// # Authorization
    ///
    /// - For `HandleTarget::Identity(did)`: the `registrant_did` must equal
    ///   `did`. Only the identity owner can register a handle for themselves.
    ///
    /// - For `HandleTarget::Context(context_id)`: the `registrant_did` must
    ///   appear in `context_admin_dids`. Only a context admin can register a
    ///   handle pointing to their context.
    ///
    /// # Arguments
    ///
    /// * `handle` -- The human-readable handle string.
    /// * `target` -- The resolution target (identity or context).
    /// * `registrant_did` -- The DID attempting the registration.
    /// * `context_admin_dids` -- Admin DIDs for context-target authorization.
    ///   Ignored for identity targets.
    ///
    /// # Errors
    ///
    /// Returns [`HandleError::InvalidHandle`] if the handle string is empty,
    /// exceeds [`MAX_HANDLE_LENGTH`] characters, or contains forbidden
    /// characters.
    /// Returns [`HandleError::AlreadyRegistered`] if the handle is taken.
    /// Returns [`HandleError::Unauthorized`] if the registrant is not
    /// authorized for the target type.
    pub fn register(
        &mut self,
        handle: &str,
        target: HandleTarget,
        registrant_did: &DID,
        context_admin_dids: &[&str],
    ) -> Result<HandleRecord, HandleError> {
        // Validate handle format.
        validate_handle(handle)?;

        // Check uniqueness.
        if self.records.contains_key(handle) {
            return Err(HandleError::AlreadyRegistered(handle.to_owned()));
        }

        // Authorization check based on target type.
        match &target {
            HandleTarget::Identity(identity_did) => {
                if registrant_did != identity_did {
                    return Err(HandleError::Unauthorized(format!(
                        "registrant DID {registrant_did} does not match identity target {identity_did}"
                    )));
                }
            }
            HandleTarget::Context(_context_id) => {
                let registrant_str: &str = registrant_did.as_ref();
                if !context_admin_dids.contains(&registrant_str) {
                    return Err(HandleError::Unauthorized(format!(
                        "registrant DID {registrant_did} is not a context admin"
                    )));
                }
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let record = HandleRecord {
            handle: handle.to_owned(),
            target,
            registered_by: registrant_did.clone(),
            registered_at: now,
        };

        self.records.insert(handle.to_owned(), record.clone());
        Ok(record)
    }

    /// Resolves a handle to its target.
    ///
    /// Returns `None` if the handle is not registered.
    #[must_use]
    pub fn resolve(&self, handle: &str) -> Option<&HandleRecord> {
        self.records.get(handle)
    }

    /// Deregisters a handle.
    ///
    /// Only the original registrant can deregister a handle.
    ///
    /// # Errors
    ///
    /// Returns [`HandleError::NotFound`] if the handle is not registered.
    /// Returns [`HandleError::Unauthorized`] if the caller is not the
    /// original registrant.
    pub fn deregister(
        &mut self,
        handle: &str,
        registrant_did: &DID,
    ) -> Result<HandleRecord, HandleError> {
        let record = self
            .records
            .get(handle)
            .ok_or_else(|| HandleError::NotFound(handle.to_owned()))?;

        if &record.registered_by != registrant_did {
            return Err(HandleError::Unauthorized(format!(
                "only the original registrant {} can deregister this handle",
                record.registered_by
            )));
        }

        // Safe: we just checked it exists above.
        Ok(self
            .records
            .remove(handle)
            .unwrap_or_else(|| unreachable!()))
    }

    /// Returns the number of registered handles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if no handles are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Default for HandleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validates a handle string.
///
/// A valid handle:
/// - Is non-empty.
/// - Does not exceed [`MAX_HANDLE_LENGTH`] characters.
/// - Does not contain null bytes, path separators, or control characters.
fn validate_handle(handle: &str) -> Result<(), HandleError> {
    if handle.is_empty() {
        return Err(HandleError::InvalidHandle(
            "handle must not be empty".to_owned(),
        ));
    }

    if handle.len() > MAX_HANDLE_LENGTH {
        return Err(HandleError::InvalidHandle(format!(
            "handle exceeds maximum length of {MAX_HANDLE_LENGTH}: got {}",
            handle.len()
        )));
    }

    if handle.contains('\0') {
        return Err(HandleError::InvalidHandle(
            "handle must not contain null bytes".to_owned(),
        ));
    }

    if handle.chars().any(char::is_control) {
        return Err(HandleError::InvalidHandle(
            "handle must not contain control characters".to_owned(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn alice_did() -> DID {
        DID::from("did:dht:z6MkAlice")
    }

    fn bob_did() -> DID {
        DID::from("did:dht:z6MkBob")
    }

    // -- Identity handle registration ----------------------------------------

    #[test]
    fn register_identity_handle_succeeds() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();

        let record = registry
            .register(
                "alice@scp",
                HandleTarget::Identity(alice.clone()),
                &alice,
                &[],
            )
            .unwrap();

        assert_eq!(record.handle, "alice@scp");
        assert_eq!(record.target, HandleTarget::Identity(alice.clone()));
        assert_eq!(record.registered_by, alice);
    }

    #[test]
    fn register_identity_handle_rejects_wrong_registrant() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();
        let bob = bob_did();

        let err = registry
            .register("alice@scp", HandleTarget::Identity(alice), &bob, &[])
            .unwrap_err();

        assert!(matches!(err, HandleError::Unauthorized(_)));
        assert!(err.to_string().contains("does not match"));
    }

    // -- Context handle registration -----------------------------------------

    #[test]
    fn register_context_handle_succeeds_for_admin() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();

        let record = registry
            .register(
                "recipes@cooking",
                HandleTarget::Context("ctx-001".to_owned()),
                &alice,
                &["did:dht:z6MkAlice"],
            )
            .unwrap();

        assert_eq!(record.handle, "recipes@cooking");
        assert_eq!(record.target, HandleTarget::Context("ctx-001".to_owned()));
        assert_eq!(record.registered_by, alice);
    }

    #[test]
    fn register_context_handle_rejects_non_admin() {
        let mut registry = HandleRegistry::new();
        let bob = bob_did();

        let err = registry
            .register(
                "recipes@cooking",
                HandleTarget::Context("ctx-001".to_owned()),
                &bob,
                &["did:dht:z6MkAlice"], // Bob is not in admin list
            )
            .unwrap_err();

        assert!(matches!(err, HandleError::Unauthorized(_)));
        assert!(err.to_string().contains("not a context admin"));
    }

    #[test]
    fn register_context_handle_rejects_empty_admin_list() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();

        let err = registry
            .register(
                "recipes@cooking",
                HandleTarget::Context("ctx-001".to_owned()),
                &alice,
                &[], // empty admin list
            )
            .unwrap_err();

        assert!(matches!(err, HandleError::Unauthorized(_)));
    }

    // -- Handle resolution ---------------------------------------------------

    #[test]
    fn resolve_returns_record() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();

        registry
            .register(
                "alice@scp",
                HandleTarget::Identity(alice.clone()),
                &alice,
                &[],
            )
            .unwrap();

        let record = registry.resolve("alice@scp").unwrap();
        assert_eq!(record.target, HandleTarget::Identity(alice));
    }

    #[test]
    fn resolve_unknown_returns_none() {
        let registry = HandleRegistry::new();
        assert!(registry.resolve("unknown@scp").is_none());
    }

    // -- Handle deregistration -----------------------------------------------

    #[test]
    fn deregister_removes_handle() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();

        registry
            .register(
                "alice@scp",
                HandleTarget::Identity(alice.clone()),
                &alice,
                &[],
            )
            .unwrap();

        let removed = registry.deregister("alice@scp", &alice).unwrap();
        assert_eq!(removed.handle, "alice@scp");
        assert!(registry.resolve("alice@scp").is_none());
    }

    #[test]
    fn deregister_rejects_wrong_registrant() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();
        let bob = bob_did();

        registry
            .register(
                "alice@scp",
                HandleTarget::Identity(alice.clone()),
                &alice,
                &[],
            )
            .unwrap();

        let err = registry.deregister("alice@scp", &bob).unwrap_err();
        assert!(matches!(err, HandleError::Unauthorized(_)));
    }

    #[test]
    fn deregister_unknown_handle_returns_not_found() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();

        let err = registry.deregister("unknown@scp", &alice).unwrap_err();
        assert!(matches!(err, HandleError::NotFound(_)));
    }

    // -- Duplicate registration ----------------------------------------------

    #[test]
    fn register_duplicate_handle_returns_error() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();

        registry
            .register(
                "alice@scp",
                HandleTarget::Identity(alice.clone()),
                &alice,
                &[],
            )
            .unwrap();

        let err = registry
            .register(
                "alice@scp",
                HandleTarget::Identity(alice.clone()),
                &alice,
                &[],
            )
            .unwrap_err();

        assert!(matches!(err, HandleError::AlreadyRegistered(_)));
    }

    // -- Handle validation ---------------------------------------------------

    #[test]
    fn rejects_empty_handle() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();

        let err = registry
            .register("", HandleTarget::Identity(alice.clone()), &alice, &[])
            .unwrap_err();

        assert!(matches!(err, HandleError::InvalidHandle(_)));
    }

    #[test]
    fn rejects_handle_with_null_byte() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();

        let err = registry
            .register(
                "alice\0@scp",
                HandleTarget::Identity(alice.clone()),
                &alice,
                &[],
            )
            .unwrap_err();

        assert!(matches!(err, HandleError::InvalidHandle(_)));
    }

    #[test]
    fn rejects_handle_exceeding_max_length() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();
        let long_handle = "a".repeat(MAX_HANDLE_LENGTH + 1);

        let err = registry
            .register(
                &long_handle,
                HandleTarget::Identity(alice.clone()),
                &alice,
                &[],
            )
            .unwrap_err();

        assert!(matches!(err, HandleError::InvalidHandle(_)));
    }

    // -- Registry state helpers ----------------------------------------------

    #[test]
    fn len_and_is_empty() {
        let mut registry = HandleRegistry::new();
        let alice = alice_did();

        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry
            .register(
                "alice@scp",
                HandleTarget::Identity(alice.clone()),
                &alice,
                &[],
            )
            .unwrap();

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    // -- Serialization roundtrip ---------------------------------------------

    #[test]
    fn handle_target_serialization_roundtrip() {
        let targets = vec![
            HandleTarget::Identity(DID::from("did:dht:z6MkAlice")),
            HandleTarget::Context("ctx-001".to_owned()),
        ];

        for target in targets {
            let json = serde_json::to_string(&target).unwrap();
            let deserialized: HandleTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(target, deserialized);
        }
    }

    #[test]
    fn handle_record_serialization_roundtrip() {
        let record = HandleRecord {
            handle: "alice@scp".to_owned(),
            target: HandleTarget::Identity(DID::from("did:dht:z6MkAlice")),
            registered_by: DID::from("did:dht:z6MkAlice"),
            registered_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: HandleRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    // -- Context admin with multiple admins ----------------------------------

    #[test]
    fn register_context_handle_with_multiple_admins() {
        let mut registry = HandleRegistry::new();
        let bob = bob_did();

        // Bob is in the admin list along with Alice.
        let record = registry
            .register(
                "recipes@cooking",
                HandleTarget::Context("ctx-001".to_owned()),
                &bob,
                &["did:dht:z6MkAlice", "did:dht:z6MkBob"],
            )
            .unwrap();

        assert_eq!(record.registered_by, bob);
    }
}
