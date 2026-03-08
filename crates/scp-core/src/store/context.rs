//! Context storage operations for `ProtocolStore`.
//!
//! Implements context state CRUD following the key convention from
//! spec section 17.3:
//!
//! ```text
//! context/{context_id}/state
//! context/{context_id}/params
//! context/{context_id}/membership/{did}
//! context/{context_id}/role/{role_name}
//! ```
//!
//! See spec sections 17.3 and 17.4.

use std::collections::HashSet;

use hex;
use scp_platform::traits::Storage;
use zeroize::Zeroize;

use scp_identity::DID;

use super::{ProtocolStore, StoreError};

// ---------------------------------------------------------------------------
// Type aliases (matching the codebase convention)
// ---------------------------------------------------------------------------

/// Context identifier. Matches `type ContextId = String` used elsewhere
/// in the codebase (e.g., `sync/mod.rs`, `event_log/mod.rs`).
type ContextId = String;

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for context state.
///
/// Format: `context/{context_id}/state`
/// See spec section 17.3.
fn context_state_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/state"))
}

/// Builds the storage key for context params.
///
/// Format: `context/{context_id}/params`
/// See spec section 17.3.
fn context_params_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/params"))
}

/// Builds the storage key for a member's membership record.
///
/// Format: `context/{context_id}/membership/{did}`
/// See spec section 17.3.
fn membership_key(context_id: &str, did: &DID) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let did_str = super::sanitize_key_component(did.as_ref())?;
    Ok(format!("context/{ctx}/membership/{did_str}"))
}

/// Builds the prefix for listing all memberships in a context.
///
/// Format: `context/{context_id}/membership/`
fn membership_prefix(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/membership/"))
}

/// Builds the storage key for a role definition within a context.
///
/// Format: `context/{context_id}/role/{role_name}`
/// See spec section 17.3.
fn role_key(context_id: &str, role_name: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let role = super::sanitize_key_component(role_name)?;
    Ok(format!("context/{ctx}/role/{role}"))
}

/// Builds the prefix for listing all roles in a context.
///
/// Format: `context/{context_id}/role/`
fn roles_prefix(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/role/"))
}

/// Builds the storage key for a sender key within a context.
///
/// Format: `context/{context_id}/sender_key/{did}`
/// See spec section 17.3.
fn sender_key_key(context_id: &str, did: &DID) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let did_str = super::sanitize_key_component(did.as_ref())?;
    Ok(format!("context/{ctx}/sender_key/{did_str}"))
}

/// Builds the prefix for listing all sender keys in a context.
///
/// Format: `context/{context_id}/sender_key/`
fn sender_key_prefix(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/sender_key/"))
}

/// Builds the storage key for broadcast context state.
///
/// Format: `context/{context_id}/broadcast_state`
/// See spec section 5.14.
fn broadcast_state_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/broadcast_state"))
}

/// Builds the storage key for an author's broadcast block list.
///
/// Format: `context/{context_id}/broadcast_block/{author_did}`
/// See spec section 5.14.8.
fn broadcast_block_key(context_id: &str, author_did: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let author = super::sanitize_key_component(author_did)?;
    Ok(format!("context/{ctx}/broadcast_block/{author}"))
}

/// Builds the storage key for a full context snapshot.
///
/// Format: `context/{context_id}/full_snapshot`
/// See spec section 17.4 and SCP-PERSIST-021.
fn full_snapshot_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/full_snapshot"))
}

/// Builds the storage key for ephemeral context durable metadata.
///
/// Format: `context/{context_id}/ephemeral_metadata`
/// See spec section 5.11 — durable metadata persists after ephemeral close.
fn ephemeral_metadata_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/ephemeral_metadata"))
}

/// Builds the prefix for all keys belonging to a context.
///
/// Format: `context/{context_id}/`
fn context_prefix(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/"))
}

// ---------------------------------------------------------------------------
// Governance persistence key helpers (ADR-031 §8)
// ---------------------------------------------------------------------------

/// Builds the storage key for a context's governance configuration.
///
/// Format: `context/{context_id}/governance/config`
/// See ADR-031 §4.
///
/// # Errors
///
/// Returns [`StoreError::InvalidKey`](super::StoreError::InvalidKey) if `context_id`
/// contains invalid key characters.
pub fn governance_config_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/governance/config"))
}

/// Builds the storage key for a specific governance proposal.
///
/// Format: `context/{context_id}/governance/proposal/{proposal_id_hex}`
/// See ADR-031 §8.
///
/// # Errors
///
/// Returns [`StoreError::InvalidKey`](super::StoreError::InvalidKey) if `context_id`
/// contains invalid key characters.
pub fn governance_proposal_key(
    context_id: &str,
    proposal_id: &[u8; 32],
) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let pid_hex = hex::encode(proposal_id);
    Ok(format!("context/{ctx}/governance/proposal/{pid_hex}"))
}

/// Builds the storage key for the pending proposal index.
///
/// Format: `context/{context_id}/governance/proposal_index/pending`
/// See ADR-031 §8.
///
/// # Errors
///
/// Returns [`StoreError::InvalidKey`](super::StoreError::InvalidKey) if `context_id`
/// contains invalid key characters.
pub fn governance_pending_index_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/governance/proposal_index/pending"))
}

/// Builds the storage key for the resolved proposal index.
///
/// Format: `context/{context_id}/governance/proposal_index/resolved`
/// See ADR-031 §8.
///
/// # Errors
///
/// Returns [`StoreError::InvalidKey`](super::StoreError::InvalidKey) if `context_id`
/// contains invalid key characters.
pub fn governance_resolved_index_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/governance/proposal_index/resolved"))
}

/// Builds the storage key for governance deadlock state.
///
/// Format: `context/{context_id}/governance/deadlock_state`
/// See ADR-031 §10.
///
/// # Errors
///
/// Returns [`StoreError::InvalidKey`](super::StoreError::InvalidKey) if `context_id`
/// contains invalid key characters.
pub fn governance_deadlock_state_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/governance/deadlock_state"))
}

// ---------------------------------------------------------------------------
// ProtocolStore — context methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Stores the state for a context.
    ///
    /// Serializes context state bytes under `context/{context_id}/state`
    /// wrapped in a `StoredValue` version envelope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_context_state(
        &self,
        context_id: &str,
        state: &[u8],
    ) -> Result<(), StoreError> {
        let key = context_state_key(context_id)?;
        self.store_value(&key, &state.to_vec()).await
    }

    /// Loads the state for a context.
    ///
    /// Returns `None` if no state exists for the given context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_context_state(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = context_state_key(context_id)?;
        self.load_value(&key).await
    }

    /// Stores the parameters for a context.
    ///
    /// Serializes context params bytes under `context/{context_id}/params`
    /// wrapped in a `StoredValue` version envelope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_context_params(
        &self,
        context_id: &str,
        params: &[u8],
    ) -> Result<(), StoreError> {
        let key = context_params_key(context_id)?;
        self.store_value(&key, &params.to_vec()).await
    }

    /// Loads the parameters for a context.
    ///
    /// Returns `None` if no params exist for the given context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_context_params(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = context_params_key(context_id)?;
        self.load_value(&key).await
    }

    /// Deletes all stored state for a context.
    ///
    /// Removes all keys under `context/{context_id}/` including state,
    /// params, memberships, roles, events, tools, etc. Returns the
    /// number of keys deleted.
    ///
    /// See spec section 17.3 on context cleanup via `delete_prefix`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn delete_context(&self, context_id: &str) -> Result<u64, StoreError> {
        let prefix = context_prefix(context_id)?;
        let mut deleted = self.storage.delete_prefix(&prefix).await?;
        // Also delete MLS state which lives under a separate namespace.
        let ctx = super::sanitize_key_component(context_id)?;
        let mls_prefix = format!("mls/{ctx}/");
        deleted += self.storage.delete_prefix(&mls_prefix).await?;
        Ok(deleted)
    }

    /// Lists all active context IDs.
    ///
    /// Scans for keys matching `context/*/state` by listing all keys
    /// with the `context/` prefix and extracting unique context IDs.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn list_active_contexts(&self) -> Result<Vec<ContextId>, StoreError> {
        let keys = self.storage.list_keys("context/").await?;
        // list_keys returns sorted order; each context has exactly one
        // /state key, so no duplicates are possible.
        let context_ids: Vec<ContextId> = keys
            .into_iter()
            .filter_map(|key| {
                let rest = key.strip_prefix("context/")?;
                if rest.ends_with("/state") {
                    let id = rest.strip_suffix("/state")?;
                    Some(id.to_owned())
                } else {
                    None
                }
            })
            .collect();
        Ok(context_ids)
    }

    /// Lists all context IDs that have a persisted full snapshot.
    ///
    /// Scans for keys matching `context/*/full_snapshot` by listing all keys
    /// with the `context/` prefix and filtering for snapshot keys. Used by
    /// [`ProtocolStorePersistence`] to implement
    /// [`ContextPersistence::list_persisted_contexts`].
    ///
    /// The returned list is a point-in-time snapshot. In a concurrent
    /// environment, contexts may be created or deleted between the list
    /// operation and subsequent access — callers must handle missing
    /// snapshots gracefully.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn list_persisted_snapshot_contexts(&self) -> Result<Vec<ContextId>, StoreError> {
        let keys = self.storage.list_keys("context/").await?;
        let context_ids: Vec<ContextId> = keys
            .into_iter()
            .filter_map(|key| {
                let rest = key.strip_prefix("context/")?;
                if rest.ends_with("/full_snapshot") {
                    let id = rest.strip_suffix("/full_snapshot")?;
                    Some(id.to_owned())
                } else {
                    None
                }
            })
            .collect();
        Ok(context_ids)
    }

    /// Stores a full context snapshot for persistence across restarts.
    ///
    /// Serializes the [`ContextSnapshot`] under
    /// `context/{context_id}/full_snapshot` as a single atomic blob.
    /// Buffer zeroization is applied after write (defense-in-depth for
    /// any key material that may be referenced in the snapshot).
    ///
    /// See SCP-PERSIST-021 and spec section 17.4.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_full_snapshot(
        &self,
        context_id: &str,
        snapshot: &crate::context::manager::ContextSnapshot,
    ) -> Result<(), StoreError> {
        let key = full_snapshot_key(context_id)?;
        let mut bytes = Self::serialize(snapshot)?;
        let result = self
            .storage
            .store(&key, &bytes)
            .await
            .map_err(StoreError::Storage);
        // Defense-in-depth: clear serialized data from memory.
        bytes.zeroize();
        result
    }

    /// Loads a full context snapshot from persistence.
    ///
    /// Returns `None` if no full snapshot has been persisted for the given
    /// context. The caller should use the returned [`ContextSnapshot`] to
    /// reconstruct `PerContextState` during restart.
    ///
    /// See SCP-PERSIST-021 and spec section 17.4.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_full_snapshot(
        &self,
        context_id: &str,
    ) -> Result<Option<crate::context::manager::ContextSnapshot>, StoreError> {
        let key = full_snapshot_key(context_id)?;
        self.load_value(&key).await
    }

    /// Stores a membership record for a DID within a context.
    ///
    /// The role string is serialized under
    /// `context/{context_id}/membership/{did}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_membership(
        &self,
        context_id: &str,
        did: &DID,
        role: &str,
    ) -> Result<(), StoreError> {
        let key = membership_key(context_id, did)?;
        self.store_value(&key, &role.to_owned()).await
    }

    /// Loads the membership role for a DID within a context.
    ///
    /// Returns `None` if the DID is not a member of the context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_membership(
        &self,
        context_id: &str,
        did: &DID,
    ) -> Result<Option<String>, StoreError> {
        let key = membership_key(context_id, did)?;
        self.load_value(&key).await
    }

    /// Lists all members and their roles for a context.
    ///
    /// Returns a vector of `(DID, role_string)` pairs.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any member record fails
    /// to deserialize.
    pub async fn list_members(&self, context_id: &str) -> Result<Vec<(DID, String)>, StoreError> {
        let prefix = membership_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;
        let mut members = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(did_str) = key.strip_prefix(&prefix) {
                let did = DID::from(did_str);
                if let Some(role) = self.load_membership(context_id, &did).await? {
                    members.push((did, role));
                }
            }
        }
        Ok(members)
    }

    /// Removes a membership record for a DID within a context.
    ///
    /// No-op if the membership does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn remove_membership(&self, context_id: &str, did: &DID) -> Result<(), StoreError> {
        let key = membership_key(context_id, did)?;
        self.storage.delete(&key).await?;
        Ok(())
    }

    /// Stores a role definition within a context.
    ///
    /// The role data is serialized under
    /// `context/{context_id}/role/{role_name}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_role(
        &self,
        context_id: &str,
        role_name: &str,
        role_data: &[u8],
    ) -> Result<(), StoreError> {
        let key = role_key(context_id, role_name)?;
        self.store_value(&key, &role_data.to_vec()).await
    }

    /// Loads a role definition from a context.
    ///
    /// Returns `None` if the role does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_role(
        &self,
        context_id: &str,
        role_name: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = role_key(context_id, role_name)?;
        self.load_value(&key).await
    }

    /// Lists all role names defined in a context.
    ///
    /// Returns role name strings extracted from stored keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn list_roles(&self, context_id: &str) -> Result<Vec<String>, StoreError> {
        let prefix = roles_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;
        let role_names: Vec<String> = keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(role_names)
    }

    // -----------------------------------------------------------------------
    // Sender key methods (SCP-PERSIST-013)
    // -----------------------------------------------------------------------

    /// Stores a sender key for a DID within a context.
    ///
    /// Serializes the sender key under
    /// `context/{context_id}/sender_key/{did}` wrapped in a
    /// `StoredValue` version envelope.
    ///
    /// See spec section 17.3 and 17.4. See SCP-PERSIST-013.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_sender_key(
        &self,
        context_id: &str,
        did: &DID,
        key: &[u8],
    ) -> Result<(), StoreError> {
        let storage_key = sender_key_key(context_id, did)?;
        // Sender keys are cryptographic material — zeroize after storage.
        self.store_value_zeroize(&storage_key, &key.to_vec()).await
    }

    /// Loads a sender key for a DID within a context.
    ///
    /// Returns `None` if no sender key exists for the given DID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_sender_key(
        &self,
        context_id: &str,
        did: &DID,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let storage_key = sender_key_key(context_id, did)?;
        self.load_value(&storage_key).await
    }

    /// Lists all sender keys for a context.
    ///
    /// Returns a vector of `(DID, sender_key_bytes)` pairs.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any sender key fails
    /// to deserialize.
    pub async fn list_sender_keys(
        &self,
        context_id: &str,
    ) -> Result<Vec<(DID, Vec<u8>)>, StoreError> {
        let prefix = sender_key_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(did_str) = key.strip_prefix(&prefix) {
                let did = DID::from(did_str);
                if let Some(sk) = self.load_sender_key(context_id, &did).await? {
                    results.push((did, sk));
                }
            }
        }
        Ok(results)
    }

    /// Removes a sender key for a DID within a context.
    ///
    /// No-op if the sender key does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn remove_sender_key(&self, context_id: &str, did: &DID) -> Result<(), StoreError> {
        let storage_key = sender_key_key(context_id, did)?;
        self.storage.delete(&storage_key).await?;
        Ok(())
    }

    /// Stores the full broadcast context state for persistence across restarts.
    ///
    /// Serializes the [`BroadcastContextSnapshot`] under
    /// `context/{context_id}/broadcast_state`. The snapshot contains the
    /// admission policy, subscriber roster, and per-author key state
    /// (including key material, epochs, and block lists).
    ///
    /// Called after each broadcast mutation (subscribe, unsubscribe, block,
    /// create) to ensure broadcast state survives process restarts.
    ///
    /// See spec section 5.14 and §17.3.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_broadcast_state(
        &self,
        context_id: &str,
        snapshot: &crate::context::broadcast::BroadcastContextSnapshot,
    ) -> Result<(), StoreError> {
        let key = broadcast_state_key(context_id)?;
        // Uses store_value_zeroize to clear serialized key material from memory.
        self.store_value_zeroize(&key, snapshot).await
    }

    /// Loads the broadcast context state from persistence.
    ///
    /// Returns `None` if no broadcast state has been persisted for the given
    /// context (either the context is not broadcast, or it has not been
    /// persisted yet). The caller should reconstruct a `BroadcastContext`
    /// from the returned snapshot using
    /// [`BroadcastContext::from_snapshot`].
    ///
    /// See spec section 5.14 and §17.3.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_broadcast_state(
        &self,
        context_id: &str,
    ) -> Result<Option<crate::context::broadcast::BroadcastContextSnapshot>, StoreError> {
        let key = broadcast_state_key(context_id)?;
        self.load_value(&key).await
    }

    /// Stores a broadcast block list for an author within a context.
    ///
    /// Persists the set of blocked subscriber DIDs under
    /// `context/{context_id}/broadcast_block/{author_did}`. The caller
    /// (typically the `ContextManager`) should invoke this after
    /// `BroadcastContext::block_subscriber` returns, using the
    /// `block_list` field from `BlockResult`.
    ///
    /// See spec section 5.14.8 for blocking semantics. See RED-016.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_broadcast_block_list(
        &self,
        context_id: &str,
        author_did: &str,
        block_list: &HashSet<String>,
    ) -> Result<(), StoreError> {
        let key = broadcast_block_key(context_id, author_did)?;
        self.store_value(&key, block_list).await
    }

    /// Loads a broadcast block list for an author within a context.
    ///
    /// Returns `None` if no block list has been persisted for the given
    /// author. The caller should pass the loaded set to
    /// `BroadcastContext::restore_block_list` during initialization.
    ///
    /// See spec section 5.14.8 for blocking semantics. See RED-016.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_broadcast_block_list(
        &self,
        context_id: &str,
        author_did: &str,
    ) -> Result<Option<HashSet<String>>, StoreError> {
        let key = broadcast_block_key(context_id, author_did)?;
        self.load_value(&key).await
    }

    /// Stores durable metadata for an ephemeral context after close.
    ///
    /// Per spec §5.11, durable metadata (participants, creation time,
    /// purpose, participation counts) persists after ephemeral close even
    /// though content and keys are destroyed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_ephemeral_metadata(
        &self,
        context_id: &str,
        metadata: &crate::context::memory_scope::EphemeralContextMetadata,
    ) -> Result<(), StoreError> {
        let key = ephemeral_metadata_key(context_id)?;
        self.store_value(&key, metadata).await
    }

    /// Loads durable metadata for an ephemeral context.
    ///
    /// Returns `None` if no ephemeral metadata has been stored for this
    /// context (either the context is not ephemeral or has not been closed).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_ephemeral_metadata(
        &self,
        context_id: &str,
    ) -> Result<Option<crate::context::memory_scope::EphemeralContextMetadata>, StoreError> {
        let key = ephemeral_metadata_key(context_id)?;
        self.load_value(&key).await
    }
}

// ---------------------------------------------------------------------------
// ProtocolStorePersistence — canonical bridge (SCP-PERSIST-021)
// ---------------------------------------------------------------------------

/// Canonical bridge from `ContextPersistence` (dyn-compatible) to the generic
/// `ProtocolStore<S>`.
///
/// Wraps `Arc<ProtocolStore<S>>` and implements the synchronous
/// [`ContextPersistence`] trait by blocking on the async `ProtocolStore`
/// methods via `tokio::task::block_in_place` + `Handle::block_on`. This is
/// safe because `ContextPersistence` methods are always called from within a
/// tokio runtime context (after the `contexts` mutex is released).
///
/// See SCP-PERSIST-021 and spec section 17.4.
pub struct ProtocolStorePersistence<S: Storage> {
    store: std::sync::Arc<ProtocolStore<S>>,
}

impl<S: Storage> ProtocolStorePersistence<S> {
    /// Creates a new bridge wrapping the given `ProtocolStore`.
    pub const fn new(store: std::sync::Arc<ProtocolStore<S>>) -> Self {
        Self { store }
    }
}

impl<S: Storage + 'static> crate::context::manager::ContextPersistence
    for ProtocolStorePersistence<S>
{
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &crate::context::manager::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        let snap = snapshot.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { store.store_full_snapshot(&ctx_id, &snap).await })
        })?;
        Ok(())
    }

    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<
        Option<crate::context::manager::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { store.load_full_snapshot(&ctx_id).await })
        })?;
        Ok(result)
    }

    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &crate::context::broadcast::BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        let snap = snapshot.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { store.store_broadcast_state(&ctx_id, &snap).await })
        })?;
        Ok(())
    }

    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<
        Option<crate::context::broadcast::BroadcastContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { store.load_broadcast_state(&ctx_id).await })
        })?;
        Ok(result)
    }

    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let store = self.store.clone();
        let ctx_id = context_id.to_owned();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { store.delete_context(&ctx_id).await })
        })?;
        Ok(())
    }

    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let store = self.store.clone();
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { store.list_persisted_snapshot_contexts().await })
        })?;
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::testing::InMemoryStorage;

    use super::*;

    fn make_store() -> ProtocolStore<InMemoryStorage> {
        ProtocolStore::new(InMemoryStorage::new())
    }

    fn test_did() -> DID {
        DID::from("did:dht:z6MkTestMember")
    }

    // -------------------------------------------------------------------
    // Context state
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_context_state_roundtrip() {
        let store = make_store();
        let state = b"context-state-data".to_vec();

        store.store_context_state("ctx-1", &state).await.unwrap();
        let loaded = store.load_context_state("ctx-1").await.unwrap();
        assert_eq!(loaded, Some(state));
    }

    #[tokio::test]
    async fn load_context_state_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_context_state("nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Context params
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_context_params_roundtrip() {
        let store = make_store();
        let params = b"context-params-data".to_vec();

        store.store_context_params("ctx-1", &params).await.unwrap();
        let loaded = store.load_context_params("ctx-1").await.unwrap();
        assert_eq!(loaded, Some(params));
    }

    #[tokio::test]
    async fn load_context_params_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_context_params("nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Context deletion
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delete_context_removes_all_state() {
        let store = make_store();
        let did = test_did();

        store.store_context_state("ctx-1", b"state").await.unwrap();
        store
            .store_context_params("ctx-1", b"params")
            .await
            .unwrap();
        store
            .store_membership("ctx-1", &did, "member")
            .await
            .unwrap();
        store
            .store_role("ctx-1", "admin", b"role-data")
            .await
            .unwrap();

        let deleted = store.delete_context("ctx-1").await.unwrap();
        assert!(deleted >= 4);

        assert!(store.load_context_state("ctx-1").await.unwrap().is_none());
        assert!(store.load_context_params("ctx-1").await.unwrap().is_none());
        assert!(
            store
                .load_membership("ctx-1", &did)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.load_role("ctx-1", "admin").await.unwrap().is_none());
    }

    // -------------------------------------------------------------------
    // Active contexts listing
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn list_active_contexts_returns_context_ids() {
        let store = make_store();

        store
            .store_context_state("ctx-a", b"state-a")
            .await
            .unwrap();
        store
            .store_context_state("ctx-b", b"state-b")
            .await
            .unwrap();
        store
            .store_context_params("ctx-c", b"params-only")
            .await
            .unwrap();

        let contexts = store.list_active_contexts().await.unwrap();
        assert_eq!(contexts, vec!["ctx-a", "ctx-b"]);
    }

    // -------------------------------------------------------------------
    // Membership
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_membership_roundtrip() {
        let store = make_store();
        let did = test_did();

        store
            .store_membership("ctx-1", &did, "admin")
            .await
            .unwrap();
        let role = store.load_membership("ctx-1", &did).await.unwrap();
        assert_eq!(role, Some("admin".to_owned()));
    }

    #[tokio::test]
    async fn load_membership_returns_none_for_non_member() {
        let store = make_store();
        let did = test_did();

        let role = store.load_membership("ctx-1", &did).await.unwrap();
        assert!(role.is_none());
    }

    #[tokio::test]
    async fn list_members_returns_all_members() {
        let store = make_store();
        let did_a = DID::from("did:dht:z6MkAlice");
        let did_b = DID::from("did:dht:z6MkBob");

        store
            .store_membership("ctx-1", &did_a, "admin")
            .await
            .unwrap();
        store
            .store_membership("ctx-1", &did_b, "member")
            .await
            .unwrap();

        let mut members = store.list_members("ctx-1").await.unwrap();
        members.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(members.len(), 2);
        assert_eq!(members[0], (did_a, "admin".to_owned()));
        assert_eq!(members[1], (did_b, "member".to_owned()));
    }

    #[tokio::test]
    async fn remove_membership_deletes_member() {
        let store = make_store();
        let did = test_did();

        store
            .store_membership("ctx-1", &did, "member")
            .await
            .unwrap();
        store.remove_membership("ctx-1", &did).await.unwrap();

        let role = store.load_membership("ctx-1", &did).await.unwrap();
        assert!(role.is_none());
    }

    // -------------------------------------------------------------------
    // Roles
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_role_roundtrip() {
        let store = make_store();
        let role_data = b"role-definition-bytes".to_vec();

        store
            .store_role("ctx-1", "moderator", &role_data)
            .await
            .unwrap();
        let loaded = store.load_role("ctx-1", "moderator").await.unwrap();
        assert_eq!(loaded, Some(role_data));
    }

    #[tokio::test]
    async fn list_roles_returns_all_role_names() {
        let store = make_store();

        store
            .store_role("ctx-1", "admin", b"admin-data")
            .await
            .unwrap();
        store
            .store_role("ctx-1", "member", b"member-data")
            .await
            .unwrap();
        store
            .store_role("ctx-1", "viewer", b"viewer-data")
            .await
            .unwrap();

        let roles = store.list_roles("ctx-1").await.unwrap();
        assert_eq!(roles, vec!["admin", "member", "viewer"]);
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn context_state_key_follows_convention() {
        assert_eq!(
            context_state_key("ctx-123").unwrap(),
            "context/ctx-123/state"
        );
    }

    #[test]
    fn context_params_key_follows_convention() {
        assert_eq!(
            context_params_key("ctx-123").unwrap(),
            "context/ctx-123/params"
        );
    }

    #[test]
    fn membership_key_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        assert_eq!(
            membership_key("ctx-123", &did).unwrap(),
            "context/ctx-123/membership/did:dht:z6MkTest"
        );
    }

    #[test]
    fn role_key_follows_convention() {
        assert_eq!(
            role_key("ctx-123", "admin").unwrap(),
            "context/ctx-123/role/admin"
        );
    }

    // -------------------------------------------------------------------
    // Sender keys (SCP-PERSIST-013)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_sender_key_roundtrip() {
        let store = make_store();
        let did = test_did();
        let key_data = vec![0xAA, 0xBB, 0xCC, 0xDD];

        store
            .store_sender_key("ctx-1", &did, &key_data)
            .await
            .unwrap();
        let loaded = store.load_sender_key("ctx-1", &did).await.unwrap();
        assert_eq!(loaded, Some(key_data));
    }

    #[tokio::test]
    async fn load_sender_key_returns_none_for_missing() {
        let store = make_store();
        let did = test_did();

        let loaded = store.load_sender_key("ctx-1", &did).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn list_sender_keys_returns_all_pairs() {
        let store = make_store();
        let did_a = DID::from("did:dht:z6MkAlice");
        let did_b = DID::from("did:dht:z6MkBob");

        store
            .store_sender_key("ctx-1", &did_a, b"key-a")
            .await
            .unwrap();
        store
            .store_sender_key("ctx-1", &did_b, b"key-b")
            .await
            .unwrap();

        let mut keys = store.list_sender_keys("ctx-1").await.unwrap();
        keys.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].0, did_a);
        assert_eq!(keys[0].1, b"key-a".to_vec());
        assert_eq!(keys[1].0, did_b);
        assert_eq!(keys[1].1, b"key-b".to_vec());
    }

    #[tokio::test]
    async fn remove_sender_key_deletes_entry() {
        let store = make_store();
        let did = test_did();

        store
            .store_sender_key("ctx-1", &did, b"key-data")
            .await
            .unwrap();
        store.remove_sender_key("ctx-1", &did).await.unwrap();

        let loaded = store.load_sender_key("ctx-1", &did).await.unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn sender_key_key_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        assert_eq!(
            sender_key_key("ctx-123", &did).unwrap(),
            "context/ctx-123/sender_key/did:dht:z6MkTest"
        );
    }

    #[test]
    fn broadcast_block_key_follows_convention() {
        assert_eq!(
            broadcast_block_key("ctx-123", "did:dht:z6MkAuthor").unwrap(),
            "context/ctx-123/broadcast_block/did:dht:z6MkAuthor"
        );
    }

    // -------------------------------------------------------------------
    // Broadcast block list persistence (RED-016)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_broadcast_block_list_roundtrip() {
        let store = make_store();
        let mut block_list = HashSet::new();
        block_list.insert("did:dht:z6MkBlocked1".to_owned());
        block_list.insert("did:dht:z6MkBlocked2".to_owned());

        store
            .store_broadcast_block_list("ctx-1", "did:dht:z6MkAuthor", &block_list)
            .await
            .unwrap();
        let loaded = store
            .load_broadcast_block_list("ctx-1", "did:dht:z6MkAuthor")
            .await
            .unwrap();

        assert_eq!(loaded, Some(block_list));
    }

    #[tokio::test]
    async fn load_broadcast_block_list_returns_none_for_missing() {
        let store = make_store();
        let loaded = store
            .load_broadcast_block_list("ctx-1", "did:dht:z6MkUnknown")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn store_broadcast_block_list_overwrites_previous() {
        let store = make_store();
        let mut first = HashSet::new();
        first.insert("did:dht:z6MkBlocked1".to_owned());

        store
            .store_broadcast_block_list("ctx-1", "did:dht:z6MkAuthor", &first)
            .await
            .unwrap();

        let mut second = HashSet::new();
        second.insert("did:dht:z6MkBlocked1".to_owned());
        second.insert("did:dht:z6MkBlocked2".to_owned());
        second.insert("did:dht:z6MkBlocked3".to_owned());

        store
            .store_broadcast_block_list("ctx-1", "did:dht:z6MkAuthor", &second)
            .await
            .unwrap();

        let loaded = store
            .load_broadcast_block_list("ctx-1", "did:dht:z6MkAuthor")
            .await
            .unwrap();
        assert_eq!(loaded, Some(second));
    }

    #[tokio::test]
    async fn delete_context_removes_broadcast_block_lists() {
        let store = make_store();
        let mut block_list = HashSet::new();
        block_list.insert("did:dht:z6MkBlocked".to_owned());

        store
            .store_broadcast_block_list("ctx-1", "did:dht:z6MkAuthor", &block_list)
            .await
            .unwrap();

        store.delete_context("ctx-1").await.unwrap();

        let loaded = store
            .load_broadcast_block_list("ctx-1", "did:dht:z6MkAuthor")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Broadcast state persistence
    // -------------------------------------------------------------------

    fn make_broadcast_snapshot() -> crate::context::broadcast::BroadcastContextSnapshot {
        use crate::context::broadcast::{
            AuthorStateSnapshot, BroadcastAdmission, BroadcastContextSnapshot, SubscriberRecord,
        };
        use crate::crypto::sender_keys::generate_sender_key;

        let mut subscribers = std::collections::HashMap::new();
        subscribers.insert(
            "did:dht:z6MkSub1".to_owned(),
            SubscriberRecord {
                subscriber_did: "did:dht:z6MkSub1".to_owned(),
                registered_at: 1_700_000_000,
                has_ucan: false,
            },
        );
        subscribers.insert(
            "did:dht:z6MkSub2".to_owned(),
            SubscriberRecord {
                subscriber_did: "did:dht:z6MkSub2".to_owned(),
                registered_at: 1_700_000_100,
                has_ucan: true,
            },
        );

        let mut block_list = HashSet::new();
        block_list.insert("did:dht:z6MkBlocked".to_owned());

        let mut authors = std::collections::HashMap::new();
        authors.insert(
            "did:dht:z6MkAuthor1".to_owned(),
            AuthorStateSnapshot {
                author_did: "did:dht:z6MkAuthor1".to_owned(),
                broadcast_key: generate_sender_key(),
                epoch: 3,
                next_sequence: 1,
                block_list,
            },
        );

        BroadcastContextSnapshot {
            context_id: "ctx-broadcast-1".to_owned(),
            admission: BroadcastAdmission::Open,
            subscribers,
            authors,
        }
    }

    #[tokio::test]
    async fn store_and_load_broadcast_state_roundtrip() {
        let store = make_store();
        let snapshot = make_broadcast_snapshot();

        store
            .store_broadcast_state("ctx-broadcast-1", &snapshot)
            .await
            .unwrap();

        let loaded = store.load_broadcast_state("ctx-broadcast-1").await.unwrap();

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.context_id, "ctx-broadcast-1");
        assert_eq!(
            loaded.admission,
            crate::context::broadcast::BroadcastAdmission::Open
        );
        assert_eq!(loaded.subscribers.len(), 2);
        assert!(loaded.subscribers.contains_key("did:dht:z6MkSub1"));
        assert!(loaded.subscribers.contains_key("did:dht:z6MkSub2"));
        assert_eq!(loaded.authors.len(), 1);
        let author = loaded.authors.get("did:dht:z6MkAuthor1").unwrap();
        assert_eq!(author.epoch, 3);
        assert!(author.block_list.contains("did:dht:z6MkBlocked"));
    }

    #[tokio::test]
    async fn load_broadcast_state_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_broadcast_state("nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn store_broadcast_state_overwrites_previous() {
        use crate::context::broadcast::BroadcastAdmission;

        let store = make_store();
        let snapshot1 = make_broadcast_snapshot();

        store
            .store_broadcast_state("ctx-broadcast-1", &snapshot1)
            .await
            .unwrap();

        // Modify snapshot: change admission and add subscriber.
        let mut snapshot2 = make_broadcast_snapshot();
        snapshot2.admission = BroadcastAdmission::Gated;
        snapshot2.subscribers.insert(
            "did:dht:z6MkSub3".to_owned(),
            crate::context::broadcast::SubscriberRecord {
                subscriber_did: "did:dht:z6MkSub3".to_owned(),
                registered_at: 1_700_000_200,
                has_ucan: true,
            },
        );

        store
            .store_broadcast_state("ctx-broadcast-1", &snapshot2)
            .await
            .unwrap();

        let loaded = store
            .load_broadcast_state("ctx-broadcast-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.admission, BroadcastAdmission::Gated);
        assert_eq!(loaded.subscribers.len(), 3);
    }

    #[tokio::test]
    async fn delete_context_removes_broadcast_state() {
        let store = make_store();
        let snapshot = make_broadcast_snapshot();

        store
            .store_broadcast_state("ctx-broadcast-1", &snapshot)
            .await
            .unwrap();

        store.delete_context("ctx-broadcast-1").await.unwrap();

        let loaded = store.load_broadcast_state("ctx-broadcast-1").await.unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn broadcast_state_key_follows_convention() {
        assert_eq!(
            broadcast_state_key("ctx-123").unwrap(),
            "context/ctx-123/broadcast_state"
        );
    }

    // -------------------------------------------------------------------
    // Full snapshot persistence (SCP-PERSIST-021)
    // -------------------------------------------------------------------

    #[test]
    fn full_snapshot_key_follows_convention() {
        assert_eq!(
            full_snapshot_key("ctx-123").unwrap(),
            "context/ctx-123/full_snapshot"
        );
    }

    fn make_context_snapshot() -> crate::context::manager::ContextSnapshot {
        use crate::context::membership::MembershipState;
        use crate::context::roles::ContextRoleState;
        use crate::context::{ContextParams, ContextState};

        let mut membership = MembershipState::new();
        membership.add_member("did:dht:z6MkCreator".into(), "admin".into(), vec![]);

        let role_state = ContextRoleState::new(
            "ctx-snap-1",
            "did:dht:z6MkCreator",
            crate::context::roles::CapabilityCeiling::new(std::iter::empty()),
            vec![],
        )
        .unwrap();

        crate::context::manager::ContextSnapshot {
            context_id: "ctx-snap-1".to_owned(),
            state: ContextState::Active,
            context_params: ContextParams::default(),
            membership,
            role_state,
            executed_proposals: std::collections::HashSet::new(),
            ttl_remaining_secs: Some(300),
            registered_tools: Vec::new(),
            write_revoked_members: std::collections::HashSet::new(),
            read_revoked_members: std::collections::HashSet::new(),
            read_exclusion_list: std::collections::HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            approved_proposals: std::collections::HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
        }
    }

    #[tokio::test]
    async fn store_and_load_full_snapshot_roundtrip() {
        let store = make_store();
        let snapshot = make_context_snapshot();

        store
            .store_full_snapshot("ctx-snap-1", &snapshot)
            .await
            .unwrap();

        let loaded = store.load_full_snapshot("ctx-snap-1").await.unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.context_id, "ctx-snap-1");
        assert_eq!(loaded.state, crate::context::ContextState::Active);
        assert_eq!(loaded.ttl_remaining_secs, Some(300));
        assert!(loaded.membership.contains("did:dht:z6MkCreator"));
    }

    #[tokio::test]
    async fn load_full_snapshot_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_full_snapshot("nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_context_removes_full_snapshot() {
        let store = make_store();
        let snapshot = make_context_snapshot();

        store
            .store_full_snapshot("ctx-snap-1", &snapshot)
            .await
            .unwrap();

        store.delete_context("ctx-snap-1").await.unwrap();

        let loaded = store.load_full_snapshot("ctx-snap-1").await.unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // ProtocolStorePersistence bridge (SCP-PERSIST-021)
    // -------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn protocol_store_persistence_context_roundtrip() {
        use crate::context::manager::ContextPersistence;

        let store = std::sync::Arc::new(make_store());
        let bridge = super::ProtocolStorePersistence::new(store);

        let snapshot = make_context_snapshot();

        bridge.persist_context("ctx-bridge-1", &snapshot).unwrap();

        let loaded = bridge.load_context("ctx-bridge-1").unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.context_id, "ctx-snap-1");
        assert_eq!(loaded.state, crate::context::ContextState::Active);
        assert_eq!(loaded.ttl_remaining_secs, Some(300));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn protocol_store_persistence_broadcast_roundtrip() {
        use crate::context::manager::ContextPersistence;

        let store = std::sync::Arc::new(make_store());
        let bridge = super::ProtocolStorePersistence::new(store);

        let snapshot = make_broadcast_snapshot();

        bridge
            .persist_broadcast("ctx-bc-bridge", &snapshot)
            .unwrap();

        let loaded = bridge.load_broadcast("ctx-bc-bridge").unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.context_id, "ctx-broadcast-1");
        assert_eq!(loaded.subscribers.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn protocol_store_persistence_delete_and_list() {
        use crate::context::manager::ContextPersistence;

        let store = std::sync::Arc::new(make_store());
        let bridge = super::ProtocolStorePersistence::new(store.clone());

        // Use store_full_snapshot (the actual persistence path used by
        // ContextManager) instead of store_context_state, so
        // list_persisted_contexts finds contexts via full_snapshot keys.
        let mut snap1 = make_context_snapshot();
        snap1.context_id = "ctx-list-1".to_owned();
        store
            .store_full_snapshot("ctx-list-1", &snap1)
            .await
            .unwrap();

        let mut snap2 = make_context_snapshot();
        snap2.context_id = "ctx-list-2".to_owned();
        store
            .store_full_snapshot("ctx-list-2", &snap2)
            .await
            .unwrap();

        let listed = bridge.list_persisted_contexts().unwrap();
        assert_eq!(listed, vec!["ctx-list-1", "ctx-list-2"]);

        bridge.delete_context("ctx-list-1").unwrap();

        let listed = bridge.list_persisted_contexts().unwrap();
        assert_eq!(listed, vec!["ctx-list-2"]);
    }

    #[test]
    fn protocol_store_persistence_is_object_safe() {
        // Compile-time dyn-compatibility check: verifies that
        // ProtocolStorePersistence can be used as a trait object.
        fn assert_object_safe(_: &dyn crate::context::manager::ContextPersistence) {}
        let store = std::sync::Arc::new(make_store());
        let bridge = super::ProtocolStorePersistence::new(store);
        assert_object_safe(&bridge);
    }
}
