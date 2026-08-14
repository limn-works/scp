//! Context storage operations for `ProtocolRepository`.
//!
//! Implements context state CRUD following the key convention from
//! spec section 17.3:
//!
//! ```text
//! context/{context_id}/state
//! context/{context_id}/params
//! context/{context_id}/membership/{did}
//! context/{context_id}/role/{role_name}
//! context/{context_id}/grace/{epoch:020d}
//! ```
//!
//! See spec sections 17.3, 17.4, and 23.11.

use hex;
use scp_platform::traits::Storage;
use zeroize::Zeroize;

use scp_did::DID;

use super::{ProtocolRepository, StoreError};

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
/// Returns `StoreError::InvalidKey` if `context_id`
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
/// Returns `StoreError::InvalidKey` if `context_id`
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
/// Returns `StoreError::InvalidKey` if `context_id`
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
/// Returns `StoreError::InvalidKey` if `context_id`
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
/// Returns `StoreError::InvalidKey` if `context_id`
/// contains invalid key characters.
pub fn governance_deadlock_state_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/governance/deadlock_state"))
}

// ---------------------------------------------------------------------------
// Epoch grace persistence key helpers (§23.11)
// ---------------------------------------------------------------------------

/// Builds the storage key for a single grace window entry.
///
/// Format: `context/{context_id}/grace/{epoch:020d}`
/// See spec §23.11: grace entries are persisted transactionally with MLS
/// group state.
fn grace_entry_key(context_id: &str, epoch: u64) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/grace/{epoch:020}"))
}

/// Builds the prefix for listing all grace entries in a context.
///
/// Format: `context/{context_id}/grace/`
fn grace_prefix(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/grace/"))
}

// ---------------------------------------------------------------------------
// ProtocolRepository — context methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
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
    /// params, memberships, roles, events, outlets, etc. Returns the
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
        // Also delete trust engine state (attestation cache, revocation state,
        // challenge results) which lives under the trust/ namespace (#502).
        let trust_prefix = format!("trust/{ctx}/");
        deleted += self.storage.delete_prefix(&trust_prefix).await?;
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
    /// [`ProtocolRepositoryContextBridge`] to implement
    /// [`crate::context::persistence::ContextPersistence::list_persisted_contexts`].
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
    /// Serializes the [`crate::context::state::ContextSnapshot`] under
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
        snapshot: &crate::context::state::ContextSnapshot,
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
    /// context. The caller should use the returned [`crate::context::state::ContextSnapshot`] to
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
    ) -> Result<Option<crate::context::state::ContextSnapshot>, StoreError> {
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
        metadata: &scp_protocol::context::memory_scope::EphemeralContextMetadata,
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
    ) -> Result<Option<scp_protocol::context::memory_scope::EphemeralContextMetadata>, StoreError>
    {
        let key = ephemeral_metadata_key(context_id)?;
        self.load_value(&key).await
    }

    // -------------------------------------------------------------------
    // Epoch grace persistence (§23.11)
    // -------------------------------------------------------------------

    /// Persists a single grace window entry under
    /// `context/{context_id}/grace/{epoch:020d}`.
    ///
    /// **Note:** The primary production persistence path for grace entries is
    /// the `ContextSnapshot` blob,
    /// which persists grace entries atomically alongside all other context
    /// state (membership, roles, governance, TTL, etc.) to ensure
    /// transactional consistency (§23.11 step 2). This individual CRUD method
    /// is available for direct-access patterns (e.g., targeted cleanup,
    /// testing, or recovery workflows) but is not called in the standard
    /// snapshot-based persistence flow.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_grace_entry(
        &self,
        context_id: &str,
        entry: &scp_mls::epoch_grace::GraceEntry,
    ) -> Result<(), StoreError> {
        let key = grace_entry_key(context_id, entry.epoch)?;
        self.store_value(&key, entry).await
    }

    /// Loads all persisted grace entries for a context from individual
    /// `context/{context_id}/grace/{epoch:020d}` keys.
    ///
    /// Returns entries sorted by epoch number.
    ///
    /// **Note:** The primary production persistence path loads grace entries
    /// from the `ContextSnapshot`
    /// blob (see `restore_context` in `context/manager.rs`). This method
    /// loads from individual storage keys and is available for direct-access
    /// patterns (e.g., recovery, diagnostics, testing) but is not called in
    /// the standard snapshot-based restore flow.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage fails.
    /// Returns [`StoreError::DeserializationFailed`] if a stored entry is
    /// corrupted.
    pub async fn load_grace_entries(
        &self,
        context_id: &str,
    ) -> Result<Vec<scp_mls::epoch_grace::GraceEntry>, StoreError> {
        let prefix = grace_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;
        let mut entries = Vec::with_capacity(keys.len());
        for key in &keys {
            if let Some(entry) = self
                .load_value::<scp_mls::epoch_grace::GraceEntry>(key)
                .await?
            {
                entries.push(entry);
            }
        }
        entries.sort_by_key(|e| e.epoch);
        Ok(entries)
    }

    /// Deletes a single grace entry for a specific epoch from the
    /// individual `context/{context_id}/grace/{epoch:020d}` key.
    ///
    /// **Note:** The primary production persistence path manages grace
    /// entries atomically within the
    /// `ContextSnapshot` blob.
    /// This individual CRUD method is available for direct-access patterns
    /// (e.g., targeted cleanup during recovery or testing) but expired
    /// entries are normally excluded at snapshot creation time rather than
    /// deleted individually.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage fails.
    pub async fn delete_grace_entry(&self, context_id: &str, epoch: u64) -> Result<(), StoreError> {
        let key = grace_entry_key(context_id, epoch)?;
        self.storage.delete(&key).await?;
        Ok(())
    }

    /// Deletes all grace entries for a context from individual
    /// `context/{context_id}/grace/` keys.
    ///
    /// **Note:** The primary production persistence path manages grace
    /// entries atomically within the
    /// `ContextSnapshot` blob.
    /// This method is available for bulk cleanup of individually-stored
    /// grace entries (e.g., during the inconsistent state fallback §23.11
    /// or migration from individual keys to the snapshot path).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage fails.
    pub async fn delete_all_grace_entries(&self, context_id: &str) -> Result<u64, StoreError> {
        let prefix = grace_prefix(context_id)?;
        let deleted = self.storage.delete_prefix(&prefix).await?;
        Ok(deleted)
    }
}

// ---------------------------------------------------------------------------
// ProtocolRepositoryContextBridge — canonical bridge (SCP-PERSIST-021)
// ---------------------------------------------------------------------------

/// Canonical bridge from `ContextPersistence` (dyn-compatible) to the generic
/// `ProtocolRepository<S>`.
///
/// Wraps `Arc<ProtocolRepository<S>>` and implements the async
/// [`crate::context::persistence::ContextPersistence`] trait by `.await`-ing
/// the async `ProtocolRepository` methods directly (ADR-049 Decision 7). The
/// former `tokio::task::block_in_place` + `Handle::block_on` sync→async shim is
/// gone — the trait is now `#[async_trait]`, so the actor `.await`s persistence
/// on its own task instead of parking a runtime worker.
///
/// See SCP-PERSIST-021 and spec section 17.4.
pub struct ProtocolRepositoryContextBridge<S: Storage> {
    store: std::sync::Arc<ProtocolRepository<S>>,
}

impl<S: Storage> ProtocolRepositoryContextBridge<S> {
    /// Creates a new bridge wrapping the given `ProtocolRepository`.
    pub const fn new(store: std::sync::Arc<ProtocolRepository<S>>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl<S: Storage + 'static> crate::context::persistence::ContextPersistence
    for ProtocolRepositoryContextBridge<S>
{
    async fn persist_context(
        &self,
        context_id: &str,
        snapshot: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.store.store_full_snapshot(context_id, snapshot).await?;
        Ok(())
    }

    async fn load_context(
        &self,
        context_id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let result = self.store.load_full_snapshot(context_id).await?;
        Ok(result)
    }

    async fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.store.delete_context(context_id).await?;
        Ok(())
    }

    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let result = self.store.list_persisted_snapshot_contexts().await?;
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// ProtocolRepositoryEventLogBridge — event log bridge (#636)
// ---------------------------------------------------------------------------

/// Canonical bridge from [`crate::context::providers::event_log::EventLogPersistence`] to the async
/// `ProtocolRepository` event log methods.
///
/// Wraps `Arc<ProtocolRepository<S>>` and implements the async
/// [`crate::context::providers::event_log::EventLogPersistence`] trait by
/// `.await`-ing the async `ProtocolRepository` methods directly (ADR-049
/// Decision 7). The former `tokio::task::block_in_place` + `Handle::block_on`
/// sync→async shim is gone — the trait is now `#[async_trait]`, so the provider
/// `.await`s persistence on its own task instead of parking a runtime worker.
///
/// See GitHub issue #636.
pub struct ProtocolRepositoryEventLogBridge<S: Storage> {
    store: std::sync::Arc<ProtocolRepository<S>>,
}

impl<S: Storage> ProtocolRepositoryEventLogBridge<S> {
    /// Creates a new bridge wrapping the given `ProtocolRepository`.
    pub const fn new(store: std::sync::Arc<ProtocolRepository<S>>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl<S: Storage + 'static> crate::context::providers::event_log::EventLogPersistence
    for ProtocolRepositoryEventLogBridge<S>
{
    async fn persist_entry(
        &self,
        context_id: &str,
        seq: usize,
        entry: &scp_event_log::Event,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.store
            .store_merkle_event_log_entry(context_id, seq, entry)
            .await?;
        Ok(())
    }

    async fn persist_entries(
        &self,
        context_id: &str,
        entries: &[scp_event_log::Event],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.store
            .store_merkle_event_log_entries(context_id, entries)
            .await?;
        Ok(())
    }

    async fn load_entries(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<scp_event_log::Event>>, Box<dyn std::error::Error + Send + Sync>> {
        let result = self.store.load_merkle_event_log_entries(context_id).await?;
        Ok(result)
    }

    async fn delete_entries(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.store
            .delete_merkle_event_log_entries(context_id)
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::in_memory::InMemoryStorage;

    use super::*;

    fn make_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
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

    fn make_context_snapshot() -> crate::context::state::ContextSnapshot {
        use scp_protocol::context::membership::MembershipState;
        use scp_protocol::context::roles::ContextRoleState;
        use scp_protocol::context::{ContextParams, ContextState};

        let mut membership = MembershipState::new();
        membership.add_member("did:dht:z6MkCreator".into(), "admin".into(), vec![]);

        let role_state = ContextRoleState::new(
            "ctx-snap-1",
            "did:dht:z6MkCreator",
            scp_protocol::context::roles::CapabilityCeiling::new(std::iter::empty()),
            vec![],
            &scp_clock::SystemClock,
        )
        .unwrap();

        crate::context::state::ContextSnapshot {
            context_id: "ctx-snap-1".to_owned(),
            creation_timestamp_secs: 1_700_000_000,
            state: ContextState::Active,
            context_params: ContextParams::default(),
            membership,
            role_state,
            event_log_merkle_root: [0u8; 32],
            executed_proposals: std::collections::HashSet::new(),
            ttl_deadline_secs: Some(300),
            registered_outlets: Vec::new(),
            read_exclusion_list: std::collections::HashSet::new(),
            outlet_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: std::collections::HashMap::new(),
            next_proposal_seq: 0,
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: false,
            mls_crypto_state: Vec::new(),
            migration_state: None,
            access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
            consequence_rules: Vec::new(),
            participation_cache: std::collections::HashMap::new(),
            velocity_tracker: None,
            velocity_tracker_state: None,
            cooldown_until: std::collections::HashMap::new(),
            proposal_timestamps: std::collections::HashMap::new(),
            message_pricing: None,
            hard_rate_limit_config: None,
            hard_rate_limit_state: std::collections::HashMap::new(),
            spending_nonce_tracker_state: std::collections::HashMap::new(),
            revoked_spending_ucan_cids: std::collections::HashSet::new(),
            pending_commits: std::collections::VecDeque::new(),
            commit_fault: None,
            checkpoint_events_since: 0,
            checkpoint_last_time_secs: 0,
            generation: 0,
            routing: crate::context::actor::state::ContextRouting::Broadcast,
            saga_pending: std::collections::HashMap::new(),
            xctx_committed_outputs: std::collections::HashMap::new(),
            xctx_committed_stream_outputs: std::collections::HashMap::new(),
            xctx_committed_invocations: std::collections::HashSet::new(),
            xctx_caller_reservations: std::collections::HashMap::new(),
            xctx_nonce_dedup: std::collections::HashMap::new(),
            caveat_counters: std::collections::HashMap::new(),
            stream_reservations: std::collections::HashMap::new(),
            broadcast: None,
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
        assert_eq!(loaded.state, scp_protocol::context::ContextState::Active);
        assert_eq!(loaded.ttl_deadline_secs, Some(300));
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
    // ProtocolRepositoryContextBridge bridge (SCP-PERSIST-021)
    // -------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn protocol_repository_persistence_context_roundtrip() {
        use crate::context::persistence::ContextPersistence;

        let store = std::sync::Arc::new(make_store());
        let bridge = super::ProtocolRepositoryContextBridge::new(store);

        let snapshot = make_context_snapshot();

        bridge
            .persist_context("ctx-bridge-1", &snapshot)
            .await
            .unwrap();

        let loaded = bridge.load_context("ctx-bridge-1").await.unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.context_id, "ctx-snap-1");
        assert_eq!(loaded.state, scp_protocol::context::ContextState::Active);
        assert_eq!(loaded.ttl_deadline_secs, Some(300));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn protocol_repository_persistence_delete_and_list() {
        use crate::context::persistence::ContextPersistence;

        let store = std::sync::Arc::new(make_store());
        let bridge = super::ProtocolRepositoryContextBridge::new(store.clone());

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

        let listed = bridge.list_persisted_contexts().await.unwrap();
        assert_eq!(listed, vec!["ctx-list-1", "ctx-list-2"]);

        bridge.delete_context("ctx-list-1").await.unwrap();

        let listed = bridge.list_persisted_contexts().await.unwrap();
        assert_eq!(listed, vec!["ctx-list-2"]);
    }

    #[test]
    fn protocol_repository_persistence_is_object_safe() {
        // Compile-time dyn-compatibility check: verifies that
        // ProtocolRepositoryContextBridge can be used as a trait object.
        fn assert_object_safe(_: &dyn crate::context::persistence::ContextPersistence) {}
        let store = std::sync::Arc::new(make_store());
        let bridge = super::ProtocolRepositoryContextBridge::new(store);
        assert_object_safe(&bridge);
    }

    // -------------------------------------------------------------------
    // ProtocolRepositoryEventLogBridge bridge (#636)
    // -------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn event_log_persistence_bridge_roundtrip() {
        use crate::context::providers::event_log::EventLogPersistence;

        let store = std::sync::Arc::new(make_store());
        let bridge = super::ProtocolRepositoryEventLogBridge::new(store);

        let entry0 = scp_event_log::Event {
            event_type: scp_event_log::EventType::ContextCreated,
            actor_did: scp_did::DID(String::new()),
            timestamp: 1_700_000_000,
            sequence: 0,
            payload: scp_event_log::EventPayload::default(),
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        };
        let entry1 = scp_event_log::Event {
            event_type: scp_event_log::EventType::MemberJoined,
            actor_did: scp_did::DID(String::new()),
            timestamp: 1_700_000_001,
            sequence: 1,
            payload: scp_event_log::EventPayload::default(),
            prev_hash: [1u8; 32],
            signature: Vec::new(),
        };

        // O(1) per-entry persist.
        bridge
            .persist_entry("ctx-bridge-el", 0, &entry0)
            .await
            .unwrap();
        bridge
            .persist_entry("ctx-bridge-el", 1, &entry1)
            .await
            .unwrap();

        let loaded = bridge.load_entries("ctx-bridge-el").await.unwrap().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(
            loaded[0].event_type,
            scp_event_log::EventType::ContextCreated
        );
        assert_eq!(loaded[1].event_type, scp_event_log::EventType::MemberJoined);

        bridge.delete_entries("ctx-bridge-el").await.unwrap();
        assert!(
            bridge
                .load_entries("ctx-bridge-el")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn event_log_persistence_bridge_bulk_persist() {
        use crate::context::providers::event_log::EventLogPersistence;

        let store = std::sync::Arc::new(make_store());
        let bridge = super::ProtocolRepositoryEventLogBridge::new(store);

        let entries = vec![
            scp_event_log::Event {
                event_type: scp_event_log::EventType::ContextCreated,
                actor_did: scp_did::DID(String::new()),
                timestamp: 1_700_000_000,
                sequence: 0,
                payload: scp_event_log::EventPayload::default(),
                prev_hash: [0u8; 32],
                signature: Vec::new(),
            },
            scp_event_log::Event {
                event_type: scp_event_log::EventType::MemberJoined,
                actor_did: scp_did::DID(String::new()),
                timestamp: 1_700_000_001,
                sequence: 1,
                payload: scp_event_log::EventPayload::default(),
                prev_hash: [1u8; 32],
                signature: Vec::new(),
            },
        ];

        bridge
            .persist_entries("ctx-bridge-bulk", &entries)
            .await
            .unwrap();

        let loaded = bridge
            .load_entries("ctx-bridge-bulk")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(
            loaded[0].event_type,
            scp_event_log::EventType::ContextCreated
        );
        assert_eq!(loaded[1].event_type, scp_event_log::EventType::MemberJoined);
    }

    #[allow(dead_code)]
    fn event_log_persistence_bridge_is_object_safe() {
        // Compile-time dyn-compatibility check.
        fn assert_object_safe(_: &dyn crate::context::providers::event_log::EventLogPersistence) {}
        let store = std::sync::Arc::new(make_store());
        let bridge = super::ProtocolRepositoryEventLogBridge::new(store);
        assert_object_safe(&bridge);
    }

    // -------------------------------------------------------------------
    // Epoch grace persistence (§23.11)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_grace_entry_roundtrip() {
        use scp_mls::epoch_grace::GraceEntry;

        let store = make_store();
        let entry = GraceEntry {
            epoch: 42,
            expires_at_unix_secs: 1_700_000_000,
        };
        store.store_grace_entry("ctx-1", &entry).await.unwrap();
        let loaded = store.load_grace_entries("ctx-1").await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], entry);
    }

    #[tokio::test]
    async fn load_grace_entries_returns_sorted_by_epoch() {
        use scp_mls::epoch_grace::GraceEntry;

        let store = make_store();
        // Store out of order.
        for &epoch in &[30, 10, 20] {
            let entry = GraceEntry {
                epoch,
                expires_at_unix_secs: 1_700_000_000 + epoch,
            };
            store.store_grace_entry("ctx-1", &entry).await.unwrap();
        }

        let loaded = store.load_grace_entries("ctx-1").await.unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].epoch, 10);
        assert_eq!(loaded[1].epoch, 20);
        assert_eq!(loaded[2].epoch, 30);
    }

    #[tokio::test]
    async fn load_grace_entries_empty_returns_empty() {
        let store = make_store();
        let loaded = store.load_grace_entries("ctx-1").await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn delete_grace_entry_removes_single_epoch() {
        use scp_mls::epoch_grace::GraceEntry;

        let store = make_store();
        for epoch in 1..=3 {
            let entry = GraceEntry {
                epoch,
                expires_at_unix_secs: 1_700_000_000 + epoch,
            };
            store.store_grace_entry("ctx-1", &entry).await.unwrap();
        }

        store.delete_grace_entry("ctx-1", 2).await.unwrap();
        let loaded = store.load_grace_entries("ctx-1").await.unwrap();
        let epochs: Vec<u64> = loaded.iter().map(|e| e.epoch).collect();
        assert_eq!(epochs, vec![1, 3]);
    }

    #[tokio::test]
    async fn delete_all_grace_entries_clears_context() {
        use scp_mls::epoch_grace::GraceEntry;

        let store = make_store();
        for epoch in 1..=5 {
            let entry = GraceEntry {
                epoch,
                expires_at_unix_secs: 1_700_000_000,
            };
            store.store_grace_entry("ctx-1", &entry).await.unwrap();
        }

        let deleted = store.delete_all_grace_entries("ctx-1").await.unwrap();
        assert_eq!(deleted, 5);

        let loaded = store.load_grace_entries("ctx-1").await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn delete_context_removes_grace_entries() {
        use scp_mls::epoch_grace::GraceEntry;

        let store = make_store();
        let entry = GraceEntry {
            epoch: 99,
            expires_at_unix_secs: 1_700_000_000,
        };
        store.store_grace_entry("ctx-1", &entry).await.unwrap();
        store.store_context_state("ctx-1", b"state").await.unwrap();

        // delete_context should remove everything including grace entries.
        store.delete_context("ctx-1").await.unwrap();

        let loaded = store.load_grace_entries("ctx-1").await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn grace_entries_isolated_per_context() {
        use scp_mls::epoch_grace::GraceEntry;

        let store = make_store();
        let entry1 = GraceEntry {
            epoch: 1,
            expires_at_unix_secs: 1_700_000_000,
        };
        let entry2 = GraceEntry {
            epoch: 2,
            expires_at_unix_secs: 1_700_000_001,
        };
        store.store_grace_entry("ctx-1", &entry1).await.unwrap();
        store.store_grace_entry("ctx-2", &entry2).await.unwrap();

        let loaded1 = store.load_grace_entries("ctx-1").await.unwrap();
        assert_eq!(loaded1.len(), 1);
        assert_eq!(loaded1[0].epoch, 1);

        let loaded2 = store.load_grace_entries("ctx-2").await.unwrap();
        assert_eq!(loaded2.len(), 1);
        assert_eq!(loaded2[0].epoch, 2);
    }

    /// Integration test: epoch grace crash recovery (§23.11).
    ///
    /// Simulates: add epochs -> persist via `ProtocolRepository` -> crash ->
    /// restart -> load entries -> restore grace store -> verify state.
    #[tokio::test]
    async fn crash_recovery_persist_and_restore() {
        use scp_mls::epoch_grace::EpochGraceStore;

        let store = make_store();

        // Phase 1: normal operation — add epochs and persist.
        let mut grace = EpochGraceStore::new();
        grace.add_epoch(100);
        grace.add_epoch(101);
        grace.add_epoch(102);

        let entries = grace.to_grace_entries();
        assert_eq!(entries.len(), 3);

        for entry in &entries {
            store.store_grace_entry("ctx-crash", entry).await.unwrap();
        }

        // Phase 2: simulate crash — drop the in-memory grace store.
        drop(grace);

        // Phase 3: recovery — load from ProtocolRepository and restore.
        let persisted = store.load_grace_entries("ctx-crash").await.unwrap();
        assert_eq!(persisted.len(), 3);

        let mut recovered = EpochGraceStore::new();
        let expired = recovered.restore_from_entries(&persisted);
        assert!(expired.is_empty(), "all entries should still be live");
        assert_eq!(recovered.len(), 3);
        assert!(recovered.is_in_grace(100));
        assert!(recovered.is_in_grace(101));
        assert!(recovered.is_in_grace(102));

        // Phase 4: clean up expired entries from storage.
        for ep in &expired {
            store.delete_grace_entry("ctx-crash", *ep).await.unwrap();
        }
    }

    /// Integration test: crash recovery with expired grace entries.
    ///
    /// Simulates a crash where some grace entries expire during downtime.
    #[tokio::test]
    async fn crash_recovery_with_expired_entries() {
        use scp_mls::epoch_grace::{EpochGraceStore, GraceEntry};

        let store = make_store();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Persist entries: one expired, one still live.
        let expired_entry = GraceEntry {
            epoch: 50,
            expires_at_unix_secs: now.saturating_sub(10),
        };
        let live_entry = GraceEntry {
            epoch: 51,
            expires_at_unix_secs: now + 20,
        };
        store
            .store_grace_entry("ctx-expired", &expired_entry)
            .await
            .unwrap();
        store
            .store_grace_entry("ctx-expired", &live_entry)
            .await
            .unwrap();

        // Recovery.
        let persisted = store.load_grace_entries("ctx-expired").await.unwrap();
        let mut recovered = EpochGraceStore::new();
        let expired = recovered.restore_from_entries(&persisted);

        assert_eq!(expired, vec![50]);
        assert_eq!(recovered.len(), 1);
        assert!(!recovered.is_in_grace(50));
        assert!(recovered.is_in_grace(51));

        // Clean up expired entries from storage.
        for ep in &expired {
            store.delete_grace_entry("ctx-expired", *ep).await.unwrap();
        }
        // Verify only live entry remains.
        let remaining = store.load_grace_entries("ctx-expired").await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].epoch, 51);
    }

    #[tokio::test]
    async fn grace_entry_key_uses_zero_padded_epoch() {
        use scp_mls::epoch_grace::GraceEntry;

        let store = make_store();
        let entry = GraceEntry {
            epoch: 42,
            expires_at_unix_secs: 1_700_000_000,
        };
        store.store_grace_entry("ctx-1", &entry).await.unwrap();

        // Verify the key format: context/{context_id}/grace/{epoch:020d}
        let keys = store
            .storage()
            .list_keys("context/ctx-1/grace/")
            .await
            .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "context/ctx-1/grace/00000000000000000042");
    }
}
