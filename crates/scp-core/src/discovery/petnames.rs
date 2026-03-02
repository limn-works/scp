//! Petname storage and resolution for identity private state.
//!
//! Implements §22.4 (Petnames): locally-assigned names for contacts and contexts,
//! stored in identity private state (§3.7). Petnames are the resolution floor --
//! they always work regardless of infrastructure availability.
//!
//! Petnames are private, instant, and require zero infrastructure. They sync
//! across devices via the identity private state event log.
//!
//! Event types for the private state event log:
//! - `SetPetname { did, name }`
//! - `RemovePetname { did }`
//! - `SetContextPetname { context_id, name }`
//! - `RemoveContextPetname { context_id }`
//!
//! See SCP-223 for the implementation story.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::identity::DID;

use super::ContextId;
use super::addressing::{
    AddressResolution, PetnameStore, ResolutionLayer, ResolutionPath, TrustLevel,
};

// ---------------------------------------------------------------------------
// PetnameEvent (§22.9.2)
// ---------------------------------------------------------------------------

/// Events for the identity private state event log related to petnames.
///
/// These events follow the existing identity private state model: append-only
/// event log, commutative operations, encrypted to the identity's own keys,
/// synced across devices.
///
/// See §22.9.2 Identity Private State Extensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PetnameEvent {
    /// Assigns a petname to a DID.
    SetPetname {
        /// The DID to assign the petname to.
        did: DID,
        /// The petname string.
        name: String,
    },
    /// Removes a petname from a DID.
    RemovePetname {
        /// The DID whose petname is being removed.
        did: DID,
    },
    /// Assigns a petname to a context.
    SetContextPetname {
        /// The context ID to assign the petname to.
        context_id: ContextId,
        /// The petname string.
        name: String,
    },
    /// Removes a petname from a context.
    RemoveContextPetname {
        /// The context ID whose petname is being removed.
        context_id: ContextId,
    },
}

// ---------------------------------------------------------------------------
// PetnameMap
// ---------------------------------------------------------------------------

/// In-memory petname storage implementing the `PetnameStore` trait.
///
/// Stores bidirectional mappings between petnames and DIDs/context IDs.
/// Petnames are the first resolution layer checked -- before any network calls.
/// A single petname may map to multiple DIDs (ambiguous, per §22.4).
///
/// Production implementations would back this with identity private state
/// persistence (§3.7).
///
/// See §22.4 Petnames.
#[derive(Debug, Default)]
pub struct PetnameMap {
    /// Maps petname -> list of DIDs (multiple DIDs possible for same name).
    did_petnames: HashMap<String, Vec<DID>>,
    /// Maps DID -> petname (for reverse lookup).
    did_to_petname: HashMap<String, String>,
    /// Maps petname -> list of context IDs.
    context_petnames: HashMap<String, Vec<ContextId>>,
    /// Maps context ID -> petname (for reverse lookup).
    context_to_petname: HashMap<String, String>,
}

impl PetnameMap {
    /// Creates a new empty petname map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a petname event, updating the internal state.
    ///
    /// This is the primary mutation method -- all changes go through events
    /// to match the append-only event log model (§3.7).
    pub fn apply_event(&mut self, event: &PetnameEvent) {
        match event {
            PetnameEvent::SetPetname { did, name } => {
                // Remove any existing petname for this DID.
                if let Some(old_name) = self.did_to_petname.remove(did.as_ref())
                    && let Some(dids) = self.did_petnames.get_mut(&old_name)
                {
                    dids.retain(|d| d != did);
                    if dids.is_empty() {
                        self.did_petnames.remove(&old_name);
                    }
                }

                // Set the new petname.
                self.did_petnames
                    .entry(name.clone())
                    .or_default()
                    .push(did.clone());
                self.did_to_petname.insert(did.to_string(), name.clone());
            }
            PetnameEvent::RemovePetname { did } => {
                if let Some(name) = self.did_to_petname.remove(did.as_ref())
                    && let Some(dids) = self.did_petnames.get_mut(&name)
                {
                    dids.retain(|d| d != did);
                    if dids.is_empty() {
                        self.did_petnames.remove(&name);
                    }
                }
            }
            PetnameEvent::SetContextPetname { context_id, name } => {
                // Remove any existing petname for this context.
                if let Some(old_name) = self.context_to_petname.remove(context_id)
                    && let Some(ids) = self.context_petnames.get_mut(&old_name)
                {
                    ids.retain(|id| id != context_id);
                    if ids.is_empty() {
                        self.context_petnames.remove(&old_name);
                    }
                }

                // Set the new petname.
                self.context_petnames
                    .entry(name.clone())
                    .or_default()
                    .push(context_id.clone());
                self.context_to_petname
                    .insert(context_id.clone(), name.clone());
            }
            PetnameEvent::RemoveContextPetname { context_id } => {
                if let Some(name) = self.context_to_petname.remove(context_id)
                    && let Some(ids) = self.context_petnames.get_mut(&name)
                {
                    ids.retain(|id| id != context_id);
                    if ids.is_empty() {
                        self.context_petnames.remove(&name);
                    }
                }
            }
        }
    }

    /// Sets a petname for a DID.
    ///
    /// Convenience method that creates and applies a `SetPetname` event.
    pub fn set_petname(&mut self, did: DID, name: String) {
        self.apply_event(&PetnameEvent::SetPetname { did, name });
    }

    /// Removes a petname from a DID.
    ///
    /// Convenience method that creates and applies a `RemovePetname` event.
    pub fn remove_petname(&mut self, did: &DID) {
        self.apply_event(&PetnameEvent::RemovePetname { did: did.clone() });
    }

    /// Sets a petname for a context.
    ///
    /// Convenience method that creates and applies a `SetContextPetname` event.
    pub fn set_context_petname(&mut self, context_id: ContextId, name: String) {
        self.apply_event(&PetnameEvent::SetContextPetname { context_id, name });
    }

    /// Removes a petname from a context.
    ///
    /// Convenience method that creates and applies a `RemoveContextPetname` event.
    pub fn remove_context_petname(&mut self, context_id: &ContextId) {
        self.apply_event(&PetnameEvent::RemoveContextPetname {
            context_id: context_id.clone(),
        });
    }

    /// Resolves a petname to DIDs.
    ///
    /// Returns all DIDs associated with this petname. Multiple results
    /// indicate ambiguity (§22.4).
    #[must_use]
    pub fn resolve_did(&self, name: &str) -> Vec<DID> {
        self.did_petnames.get(name).cloned().unwrap_or_default()
    }

    /// Resolves a petname to context IDs.
    ///
    /// Returns all context IDs associated with this petname.
    #[must_use]
    pub fn resolve_context(&self, name: &str) -> Vec<ContextId> {
        self.context_petnames.get(name).cloned().unwrap_or_default()
    }

    /// Looks up the petname for a given DID.
    ///
    /// Returns `None` if no petname is assigned.
    #[must_use]
    pub fn petname_for_did(&self, did: &DID) -> Option<&str> {
        self.did_to_petname.get(did.as_ref()).map(String::as_str)
    }

    /// Looks up the petname for a given context ID.
    ///
    /// Returns `None` if no petname is assigned.
    #[must_use]
    pub fn petname_for_context(&self, context_id: &ContextId) -> Option<&str> {
        self.context_to_petname.get(context_id).map(String::as_str)
    }

    /// Returns the total number of DID petnames.
    #[must_use]
    pub fn did_petname_count(&self) -> usize {
        self.did_to_petname.len()
    }

    /// Returns the total number of context petnames.
    #[must_use]
    pub fn context_petname_count(&self) -> usize {
        self.context_to_petname.len()
    }
}

impl PetnameStore for PetnameMap {
    fn resolve_petname(
        &self,
        name: &str,
    ) -> Result<Vec<AddressResolution>, crate::time::ClockError> {
        let now = crate::time::now_secs()?;

        let mut results = Vec::new();

        // Resolve DIDs.
        for did in self.resolve_did(name) {
            results.push(AddressResolution::Identity {
                did,
                trust_level: TrustLevel::LocalPetname,
                resolution_path: ResolutionPath {
                    layer: ResolutionLayer::Petname,
                    source: "local".to_owned(),
                    source_id: None,
                    resolved_at: now,
                },
            });
        }

        // Resolve context IDs.
        for context_id in self.resolve_context(name) {
            results.push(AddressResolution::Context {
                context_id,
                relay_urls: Vec::new(),
                mode: None,
                trust_level: TrustLevel::LocalPetname,
                resolution_path: ResolutionPath {
                    layer: ResolutionLayer::Petname,
                    source: "local".to_owned(),
                    source_id: None,
                    resolved_at: now,
                },
            });
        }

        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- PetnameEvent serialization ------------------------------------------

    #[test]
    fn petname_event_set_serialization_roundtrip() {
        let event = PetnameEvent::SetPetname {
            did: DID::from("did:dht:zAlice"),
            name: "alice".to_owned(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: PetnameEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn petname_event_remove_serialization_roundtrip() {
        let event = PetnameEvent::RemovePetname {
            did: DID::from("did:dht:zAlice"),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: PetnameEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn petname_event_set_context_serialization_roundtrip() {
        let event = PetnameEvent::SetContextPetname {
            context_id: "ctx-recipes".to_owned(),
            name: "recipes".to_owned(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: PetnameEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn petname_event_remove_context_serialization_roundtrip() {
        let event = PetnameEvent::RemoveContextPetname {
            context_id: "ctx-recipes".to_owned(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: PetnameEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    // -- PetnameMap: set and resolve DID petnames ----------------------------

    #[test]
    fn set_petname_and_resolve_returns_did() {
        let mut map = PetnameMap::new();
        map.set_petname(DID::from("did:dht:zAlice"), "alice".to_owned());

        let dids = map.resolve_did("alice");
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], "did:dht:zAlice");
    }

    #[test]
    fn resolve_nonexistent_petname_returns_empty() {
        let map = PetnameMap::new();
        assert!(map.resolve_did("nonexistent").is_empty());
    }

    #[test]
    fn multiple_dids_same_petname_returns_all() {
        let mut map = PetnameMap::new();
        map.set_petname(DID::from("did:dht:zAlice1"), "bob".to_owned());
        map.set_petname(DID::from("did:dht:zAlice2"), "bob".to_owned());

        let dids = map.resolve_did("bob");
        assert_eq!(dids.len(), 2);
    }

    #[test]
    fn set_petname_replaces_previous_for_same_did() {
        let mut map = PetnameMap::new();
        let alice = DID::from("did:dht:zAlice");

        map.set_petname(alice.clone(), "old-name".to_owned());
        map.set_petname(alice, "new-name".to_owned());

        assert!(map.resolve_did("old-name").is_empty());
        assert_eq!(map.resolve_did("new-name").len(), 1);
    }

    // -- PetnameMap: remove DID petnames ------------------------------------

    #[test]
    fn remove_petname_clears_mapping() {
        let mut map = PetnameMap::new();
        let alice = DID::from("did:dht:zAlice");
        map.set_petname(alice.clone(), "alice".to_owned());

        map.remove_petname(&alice);

        assert!(map.resolve_did("alice").is_empty());
        assert!(map.petname_for_did(&alice).is_none());
    }

    #[test]
    fn remove_nonexistent_petname_is_noop() {
        let mut map = PetnameMap::new();
        let alice = DID::from("did:dht:zAlice");
        map.remove_petname(&alice);
        assert_eq!(map.did_petname_count(), 0);
    }

    // -- PetnameMap: context petnames ---------------------------------------

    #[test]
    fn set_context_petname_and_resolve() {
        let mut map = PetnameMap::new();
        map.set_context_petname("ctx-recipes".to_owned(), "recipes".to_owned());

        let ids = map.resolve_context("recipes");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "ctx-recipes");
    }

    #[test]
    fn remove_context_petname_clears_mapping() {
        let mut map = PetnameMap::new();
        let context_id = "ctx-recipes".to_owned();
        map.set_context_petname(context_id.clone(), "recipes".to_owned());
        map.remove_context_petname(&context_id);

        assert!(map.resolve_context("recipes").is_empty());
        assert!(map.petname_for_context(&context_id).is_none());
    }

    // -- PetnameMap: reverse lookup -----------------------------------------

    #[test]
    fn petname_for_did_returns_assigned_name() {
        let mut map = PetnameMap::new();
        let alice = DID::from("did:dht:zAlice");
        map.set_petname(alice.clone(), "alice".to_owned());

        assert_eq!(map.petname_for_did(&alice), Some("alice"));
    }

    #[test]
    fn petname_for_context_returns_assigned_name() {
        let mut map = PetnameMap::new();
        let context_id = "ctx-recipes".to_owned();
        map.set_context_petname(context_id.clone(), "recipes".to_owned());

        assert_eq!(map.petname_for_context(&context_id), Some("recipes"));
    }

    // -- PetnameMap: counts -------------------------------------------------

    #[test]
    fn did_petname_count_tracks_correctly() {
        let mut map = PetnameMap::new();
        assert_eq!(map.did_petname_count(), 0);

        map.set_petname(DID::from("did:dht:zAlice"), "alice".to_owned());
        assert_eq!(map.did_petname_count(), 1);

        map.set_petname(DID::from("did:dht:zBob"), "bob".to_owned());
        assert_eq!(map.did_petname_count(), 2);

        map.remove_petname(&DID::from("did:dht:zAlice"));
        assert_eq!(map.did_petname_count(), 1);
    }

    #[test]
    fn context_petname_count_tracks_correctly() {
        let mut map = PetnameMap::new();
        assert_eq!(map.context_petname_count(), 0);

        map.set_context_petname("ctx-1".to_owned(), "one".to_owned());
        assert_eq!(map.context_petname_count(), 1);
    }

    // -- PetnameMap: apply_event --------------------------------------------

    #[test]
    fn apply_event_set_petname() {
        let mut map = PetnameMap::new();
        map.apply_event(&PetnameEvent::SetPetname {
            did: DID::from("did:dht:zAlice"),
            name: "alice".to_owned(),
        });

        assert_eq!(map.resolve_did("alice").len(), 1);
    }

    #[test]
    fn apply_event_remove_petname() {
        let mut map = PetnameMap::new();
        let alice = DID::from("did:dht:zAlice");
        map.set_petname(alice.clone(), "alice".to_owned());

        map.apply_event(&PetnameEvent::RemovePetname { did: alice });

        assert!(map.resolve_did("alice").is_empty());
    }

    // -- PetnameStore trait implementation -----------------------------------

    #[test]
    fn petname_store_resolve_returns_identity_resolutions() {
        let mut map = PetnameMap::new();
        map.set_petname(DID::from("did:dht:zAlice"), "alice".to_owned());

        let results = map.resolve_petname("alice").unwrap();
        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            AddressResolution::Identity {
                did,
                trust_level: TrustLevel::LocalPetname,
                ..
            } if did == "did:dht:zAlice"
        ));
    }

    #[test]
    fn petname_store_resolve_returns_context_resolutions() {
        let mut map = PetnameMap::new();
        map.set_context_petname("ctx-recipes".to_owned(), "recipes".to_owned());

        let results = map.resolve_petname("recipes").unwrap();
        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            AddressResolution::Context {
                context_id,
                trust_level: TrustLevel::LocalPetname,
                ..
            } if context_id == "ctx-recipes"
        ));
    }

    #[test]
    fn petname_store_resolve_returns_both_identity_and_context() {
        let mut map = PetnameMap::new();
        map.set_petname(DID::from("did:dht:zAlice"), "shared".to_owned());
        map.set_context_petname("ctx-shared".to_owned(), "shared".to_owned());

        let results = map.resolve_petname("shared").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn petname_store_resolve_empty_returns_empty() {
        let map = PetnameMap::new();
        let results = map.resolve_petname("nonexistent").unwrap();
        assert!(results.is_empty());
    }
}
