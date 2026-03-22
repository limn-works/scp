//! DID-to-DID blocking orchestration with cross-context propagation.
//!
//! Implements Tier 1 (in-context) and Tier 2 (global) blocking per spec
//! §3.6, §9.16.3, and §9.16.7. Each block executes a three-layer protocol:
//!
//! - **Layer 1:** Sender key rotation excluding the target via
//!   [`crate::crypto::sender_keys::key_protocol::rotate_sender_key_for_block`].
//! - **Layer 2:** SDK-mandated state destruction event emitted so the
//!   target's SDK destroys cached material (§9.16.7).
//! - **Layer 3:** Target's access key deleted from the blocker's key store
//!   (§9.17).
//!
//! Tier 2 (global) blocks propagate to all shared contexts — contexts
//! where both the blocker and target are members. Propagation is
//! best-effort and idempotent: offline contexts are queued for execution
//! on reconnection. The identity private state event log is authoritative;
//! per-context enforcement is the mechanism.
//!
//! Blocking is bidirectional: when Alice blocks Dave, both Alice and Dave
//! rotate their sender keys excluding each other. The block notification
//! is signed to prevent forgery (§9.16.3 step 4).
//!
//! See spec §3.6 (Social Graph), §3.7.1 (Block List Storage),
//! §9.16.3 (Block Protocol), §9.16.7 (SDK-Mandated State Destruction),
//! §9.17 (Content Access Key Layer), ADR-038.

use std::collections::HashSet;
use std::hash::BuildHasher;

use serde::{Deserialize, Serialize};

use scp_identity::DID;
use scp_platform::traits::{KeyCustody, KeyHandle};

use crate::crypto::sender_keys::{
    RotateForBlockParams, RotateForBlockResult, SenderKeyError, rotate_sender_key_for_block,
    send_block_notification,
};
use crate::identity::SigningKeyId;
use crate::identity::block_list::{BlockListEvent, BlockListState};
use scp_primitives::Clock;

// ---------------------------------------------------------------------------
// BlockOrchestrationError
// ---------------------------------------------------------------------------

/// Errors produced by blocking orchestration operations.
///
/// Wraps underlying sender key errors, adding orchestration-level
/// failure modes (context enumeration failures, access key deletion).
#[derive(Debug, thiserror::Error)]
pub enum BlockOrchestrationError {
    /// Sender key rotation (Layer 1) failed.
    #[error("sender key rotation failed: {0}")]
    SenderKeyRotation(#[from] SenderKeyError),

    /// The blocker is not a member of the specified context.
    #[error("blocker {blocker} is not a member of context {context_id}")]
    BlockerNotInContext {
        /// The blocker's DID.
        blocker: String,
        /// The context ID.
        context_id: String,
    },

    /// The target is not a member of the specified context.
    #[error("target {target} is not a member of context {context_id}")]
    TargetNotInContext {
        /// The target's DID.
        target: String,
        /// The context ID.
        context_id: String,
    },
}

// ---------------------------------------------------------------------------
// BlockInContextResult — result of executing Tier 1 block in a single context
// ---------------------------------------------------------------------------

/// Result of executing the three-layer block protocol in a single context.
///
/// Returned by [`block_did_in_context`]. Contains the artifacts needed
/// for the caller to broadcast the epoch advance and block notification
/// to context members.
///
/// See spec §9.16.3.
#[derive(Debug)]
pub struct BlockInContextResult {
    /// The context where the block was executed.
    pub context_id: String,

    /// Layer 1 result: new sender key, epoch, and epoch advance message.
    pub rotation_result: RotateForBlockResult,

    /// Layer 2: serialized signed block notification for the target.
    /// The target's SDK verifies this and destroys cached material
    /// per §9.16.7.
    pub block_notification: Vec<u8>,

    /// Layer 2 event: SDK-mandated state destruction required.
    /// The blocker's SDK must also destroy cached material from the
    /// target (bidirectional — both sides destroy each other's cached
    /// content).
    pub destruction_event: StateDestructionEvent,

    /// Layer 3: whether the target's access key was marked for deletion.
    /// The caller must execute the actual deletion from the access key
    /// store.
    pub access_key_deletion_required: bool,

    /// Block list event to record in identity private state.
    pub block_list_event: BlockListEvent,
}

// ---------------------------------------------------------------------------
// StateDestructionEvent — SDK-mandated destruction (Layer 2)
// ---------------------------------------------------------------------------

/// Event signaling that the SDK must destroy locally cached material
/// from the specified DID per §9.16.7.
///
/// When Alice blocks Dave, Alice's SDK emits this event for Dave's content,
/// and Dave's SDK (upon receiving and verifying the signed block
/// notification) emits this event for Alice's content.
///
/// The SDK must:
/// 1. Delete all cached sender key epochs from the specified DID.
/// 2. Delete all decrypted message content from the specified DID.
/// 3. Delete the specified DID's access key (if access keys are in use).
///
/// Destruction MUST occur before processing subsequent messages (§9.16.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDestructionEvent {
    /// The context where destruction applies.
    pub context_id: String,

    /// The DID whose cached material must be destroyed.
    pub target_did: DID,

    /// The DID of the party that initiated the block.
    pub blocker_did: DID,

    /// Unix timestamp (milliseconds) when the destruction was triggered.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// GlobalBlockResult — result of Tier 2 global block
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// GlobalBlockParams — parameter struct for block_did_global
// ---------------------------------------------------------------------------

/// Parameters for [`block_did_global`].
///
/// Groups the non-cryptographic parameters to avoid excessive argument
/// count (clippy `too_many_arguments`).
pub struct GlobalBlockParams<'a> {
    /// The DID of the member initiating the block.
    pub blocker_did: &'a str,
    /// The DID of the member being blocked.
    pub target_did: &'a str,
    /// Context IDs where both blocker and target are members.
    pub shared_context_ids: &'a [String],
    /// Which DID verification method produced the signature.
    pub signer_key_ref: SigningKeyId,
}

/// Result of executing a global (Tier 2) block across all shared contexts.
///
/// Returned by [`block_did_global`]. Contains per-context results and
/// any contexts that could not be reached (offline/queued for later).
///
/// See spec §3.6 (Tier 2) and §3.7.1 (block list propagation).
#[derive(Debug)]
pub struct GlobalBlockResult {
    /// The global block list event recorded in identity private state.
    pub block_list_event: BlockListEvent,

    /// Per-context block results for contexts that were successfully
    /// processed.
    pub context_results: Vec<BlockInContextResult>,

    /// Context IDs where the block could not be executed (offline,
    /// errors, etc.). These are queued for execution on reconnection.
    /// Propagation is best-effort per spec §3.7.1.
    pub pending_contexts: Vec<PendingBlockContext>,
}

/// A context where a block could not be executed and is queued for
/// later propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBlockContext {
    /// The context ID where the block is pending.
    pub context_id: String,

    /// The reason the block could not be executed.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// BlockInContextParams — parameter struct for block_did_in_context
// ---------------------------------------------------------------------------

/// Parameters for [`block_did_in_context`].
///
/// Groups the non-cryptographic parameters to avoid excessive argument
/// count (clippy `too_many_arguments`).
pub struct BlockInContextParams<'a> {
    /// The DID of the member initiating the block.
    pub blocker_did: &'a str,
    /// The DID of the member being blocked.
    pub target_did: &'a str,
    /// The context in which the block applies.
    pub context_id: &'a str,
    /// The blocker's current sender key epoch in this context.
    pub current_epoch: u64,
    /// Which DID verification method produced the signature
    /// (`#active` or `#agent`).
    pub signer_key_ref: SigningKeyId,
}

// ---------------------------------------------------------------------------
// block_did_in_context — Tier 1 single-context block (three-layer protocol)
// ---------------------------------------------------------------------------

/// Executes the three-layer block protocol for a single context (Tier 1).
///
/// **Layer 1:** Rotates the blocker's sender key excluding the target via
/// [`rotate_sender_key_for_block`]. The target can no longer obtain the
/// blocker's new sender key.
///
/// **Layer 2:** Generates a signed block notification for the target
/// and a [`StateDestructionEvent`] for the blocker's SDK to destroy
/// cached material from the target.
///
/// **Layer 3:** Signals that the target's access key must be deleted
/// from the blocker's key store. The caller is responsible for executing
/// the actual deletion.
///
/// **Ordering invariant (§9.16.3 step 1):** The block list MUST be
/// updated before this function is called. The `block_list` parameter
/// is mutated by the underlying `rotate_sender_key_for_block` to add
/// the target — ensuring the block list is authoritative before the
/// `SenderKeyEpochAdvance` is published.
///
/// **Bidirectional (§9.16.3 step 6):** The block notification triggers
/// the target's SDK to rotate their sender key excluding the blocker.
/// This function handles the blocker's side; the target's side is
/// handled by their SDK upon receiving and verifying the notification.
///
/// # Arguments
///
/// * `key_custody` — Key custody provider for signing operations.
/// * `signing_key` — The blocker's Active Signing Key or Agent Signing
///   Key handle (either is valid per ADR-039).
/// * `params` — Block parameters (blocker DID, target DID, context ID,
///   current epoch, signer key ref).
/// * `block_list` — The blocker's sender key block list for this context.
///   Mutated to add the target.
///
/// # Errors
///
/// Returns [`BlockOrchestrationError::SenderKeyRotation`] if sender key
/// rotation or block notification signing fails.
pub async fn block_did_in_context<S: BuildHasher + Send + Sync>(
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    params: &BlockInContextParams<'_>,
    block_list: &mut HashSet<String, S>,
    clock: &dyn Clock,
) -> Result<BlockInContextResult, BlockOrchestrationError> {
    let timestamp = clock.now_millis();

    // Layer 1: Rotate sender key excluding the target.
    // This also adds the target to the block_list (ordering invariant).
    let rotate_params = RotateForBlockParams {
        context_id: params.context_id,
        sender_did: params.blocker_did,
        current_epoch: params.current_epoch,
        blocked_did: params.target_did,
        signer_key_ref: params.signer_key_ref,
    };
    let rotation_result =
        rotate_sender_key_for_block(key_custody, signing_key, &rotate_params, block_list).await?;

    // Layer 2a: Generate signed block notification for the target.
    let block_notification = send_block_notification(
        key_custody,
        signing_key,
        params.context_id,
        params.blocker_did,
        params.target_did,
        params.signer_key_ref,
        clock,
    )
    .await?;

    // Layer 2b: Emit destruction event for the blocker's SDK.
    // The blocker must destroy cached material from the target.
    let destruction_event = StateDestructionEvent {
        context_id: params.context_id.to_owned(),
        target_did: DID::from(params.target_did),
        blocker_did: DID::from(params.blocker_did),
        timestamp,
    };

    // Layer 3: Signal access key deletion required.
    // The caller must delete the target's access key from the store.
    let access_key_deletion_required = true;

    // Record per-context block list event.
    let block_list_event = BlockListEvent::BlockDIDInContext {
        target_did: DID::from(params.target_did),
        context_id: params.context_id.to_owned(),
        timestamp,
    };

    Ok(BlockInContextResult {
        context_id: params.context_id.to_owned(),
        rotation_result,
        block_notification,
        destruction_event,
        access_key_deletion_required,
        block_list_event,
    })
}

// ---------------------------------------------------------------------------
// block_did_global — Tier 2 global block with cross-context propagation
// ---------------------------------------------------------------------------

/// Executes a global (Tier 2) block: stores the block in identity private
/// state and propagates to all shared contexts.
///
/// **Propagation (§3.7.1):** Enumerates all contexts where both the
/// blocker and the target are members, then executes the Tier 1 block
/// protocol ([`block_did_in_context`]) in each.
///
/// **Idempotent:** Re-executing against an already-blocked context is
/// a no-op (the context is skipped if the target is already in the
/// per-context block list).
///
/// **Best-effort:** Contexts that fail (offline, errors) are recorded
/// in [`GlobalBlockResult::pending_contexts`] for execution on
/// reconnection.
///
/// # Arguments
///
/// * `key_custody` — Key custody provider for signing operations.
/// * `signing_key` — The blocker's Active Signing Key or Agent Signing
///   Key handle.
/// * `params` — Global block parameters (blocker DID, target DID,
///   shared context IDs, signer key ref).
/// * `block_list_state` — The blocker's current block list state (for
///   idempotency checks).
/// * `per_context_block_lists` — Mutable map of `context_id` to sender key
///   block lists. Each context's block list is mutated during propagation.
/// * `per_context_epochs` — Map of `context_id` to blocker's current sender
///   key epoch in that context.
///
/// # Errors
///
/// Individual context failures do NOT cause the global block to fail.
/// They are recorded in `pending_contexts`. The global block list event
/// is always recorded.
///
#[allow(clippy::implicit_hasher)]
pub async fn block_did_global(
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    params: &GlobalBlockParams<'_>,
    block_list_state: &BlockListState,
    per_context_block_lists: &mut std::collections::HashMap<String, HashSet<String>>,
    per_context_epochs: &std::collections::HashMap<String, u64>,
    clock: &dyn Clock,
) -> Result<GlobalBlockResult, BlockOrchestrationError> {
    let timestamp = clock.now_millis();

    // Record global block event in identity private state.
    let block_list_event = BlockListEvent::BlockDID {
        target_did: DID::from(params.target_did),
        timestamp,
    };

    let mut context_results = Vec::new();
    let mut pending_contexts = Vec::new();

    // Propagate to each shared context.
    for context_id in params.shared_context_ids {
        // Idempotency: skip if already blocked in this context.
        if block_list_state.is_blocked_in_context(&DID::from(params.target_did), context_id) {
            continue;
        }

        // Get or create the per-context block list.
        let context_block_list = per_context_block_lists
            .entry(context_id.clone())
            .or_default();

        // Get the current epoch for this context.
        let current_epoch = per_context_epochs.get(context_id).copied().unwrap_or(0);

        // Execute Tier 1 protocol in this context.
        let ctx_params = BlockInContextParams {
            blocker_did: params.blocker_did,
            target_did: params.target_did,
            context_id,
            current_epoch,
            signer_key_ref: params.signer_key_ref,
        };
        match block_did_in_context(
            key_custody,
            signing_key,
            &ctx_params,
            context_block_list,
            clock,
        )
        .await
        {
            Ok(result) => {
                context_results.push(result);
            }
            Err(e) => {
                // Best-effort: record failure for later retry.
                pending_contexts.push(PendingBlockContext {
                    context_id: context_id.clone(),
                    reason: e.to_string(),
                });
            }
        }
    }

    Ok(GlobalBlockResult {
        block_list_event,
        context_results,
        pending_contexts,
    })
}

// ---------------------------------------------------------------------------
// process_received_block_notification — target-side handler
// ---------------------------------------------------------------------------

/// Parameters for [`process_received_block_notification`].
///
/// Groups the non-cryptographic parameters to avoid excessive argument
/// count (clippy `too_many_arguments`).
pub struct ReceivedBlockParams<'a> {
    /// The DID of the target (the member being blocked).
    pub target_did: &'a str,
    /// The DID of the member who initiated the block.
    pub blocker_did: &'a str,
    /// The context where the block applies.
    pub context_id: &'a str,
    /// The target's current sender key epoch.
    pub current_epoch: u64,
    /// Which DID verification method to use for the target's epoch
    /// advance signature.
    pub signer_key_ref: SigningKeyId,
}

/// Processes a received and verified block notification on the target's side.
///
/// When a block notification is received and verified (§9.16.3 step 6),
/// the target's SDK must:
///
/// 1. Rotate their own sender key excluding the blocker (bidirectional).
/// 2. Destroy cached material from the blocker (Layer 2, §9.16.7).
/// 3. Delete the blocker's access key (Layer 3).
///
/// This function handles step 1 (sender key rotation) and emits the
/// destruction event (step 2). The caller handles steps 2 and 3
/// (cache purge + access key deletion).
///
/// # Arguments
///
/// * `key_custody` — Key custody provider for signing operations.
/// * `signing_key` — The target's Active Signing Key or Agent Signing
///   Key handle.
/// * `params` — Block notification parameters (target DID, blocker DID,
///   context ID, current epoch, signer key ref).
/// * `block_list` — The target's sender key block list for this context.
///   Mutated to add the blocker.
///
/// # Errors
///
/// Returns [`BlockOrchestrationError::SenderKeyRotation`] if sender key
/// rotation fails.
pub async fn process_received_block_notification<S: BuildHasher + Send + Sync>(
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    params: &ReceivedBlockParams<'_>,
    block_list: &mut HashSet<String, S>,
    clock: &dyn Clock,
) -> Result<ReceivedBlockResult, BlockOrchestrationError> {
    let timestamp = clock.now_millis();

    // Step 1: Rotate the target's sender key excluding the blocker.
    let rotate_params = RotateForBlockParams {
        context_id: params.context_id,
        sender_did: params.target_did,
        current_epoch: params.current_epoch,
        blocked_did: params.blocker_did,
        signer_key_ref: params.signer_key_ref,
    };
    let rotation_result =
        rotate_sender_key_for_block(key_custody, signing_key, &rotate_params, block_list).await?;

    // Step 2: Emit destruction event — the target must destroy cached
    // material from the blocker.
    let destruction_event = StateDestructionEvent {
        context_id: params.context_id.to_owned(),
        target_did: DID::from(params.blocker_did),
        blocker_did: DID::from(params.blocker_did),
        timestamp,
    };

    Ok(ReceivedBlockResult {
        rotation_result,
        destruction_event,
        access_key_deletion_required: true,
    })
}

/// Result of processing a received block notification on the target's side.
///
/// The target's SDK must:
/// 1. Broadcast the epoch advance from `rotation_result.epoch_advance_message`.
/// 2. Execute the destruction described by `destruction_event`.
/// 3. Delete the blocker's access key if `access_key_deletion_required`.
#[derive(Debug)]
pub struct ReceivedBlockResult {
    /// The target's new sender key and epoch advance notification.
    pub rotation_result: RotateForBlockResult,

    /// SDK-mandated destruction event — destroy the blocker's cached
    /// material.
    pub destruction_event: StateDestructionEvent,

    /// Whether the blocker's access key should be deleted from the
    /// target's key store.
    pub access_key_deletion_required: bool,
}

// ---------------------------------------------------------------------------
// is_block_effective — check if a block is already active
// ---------------------------------------------------------------------------

/// Checks whether a DID is effectively blocked in a context, considering
/// both per-context (Tier 1) and global (Tier 2) block lists.
///
/// Returns `true` if the target is blocked in the specified context
/// (Tier 1) OR is globally blocked (Tier 2). This is the check that
/// [`crate::crypto::sender_keys::handle_sender_key_request`] should use
/// to deny key distribution (§9.16.3 step 5).
///
/// # Arguments
///
/// * `block_list_state` — The blocker's current block list state.
/// * `target` — The DID to check.
/// * `context_id` — The context to check.
#[must_use]
pub fn is_block_effective(
    block_list_state: &BlockListState,
    target: &DID,
    context_id: &str,
) -> bool {
    block_list_state.is_globally_blocked(target)
        || block_list_state.is_blocked_in_context(target, context_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_platform::testing::InMemoryKeyCustody;

    fn did(s: &str) -> DID {
        DID::from(s)
    }

    /// Creates an `InMemoryKeyCustody` with a signing key, returning
    /// the custody instance and the key handle.
    async fn make_custody_and_key() -> (InMemoryKeyCustody, KeyHandle) {
        let custody = InMemoryKeyCustody::new();
        let handle = custody
            .generate_keypair(scp_platform::traits::KeyType::Ed25519)
            .await
            .expect("key generation should succeed");
        (custody, handle)
    }

    // -----------------------------------------------------------------------
    // Tier 1: block_did_in_context tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn tier1_block_executes_three_layers() {
        let (custody, key) = make_custody_and_key().await;
        let mut block_list = HashSet::new();

        let params = BlockInContextParams {
            blocker_did: "did:dht:alice",
            target_did: "did:dht:dave",
            context_id: "ctx-1",
            current_epoch: 0,
            signer_key_ref: SigningKeyId::Active,
        };
        let clock = scp_primitives::SystemClock;
        let result = block_did_in_context(&custody, &key, &params, &mut block_list, &clock)
            .await
            .expect("block should succeed");

        // Layer 1: sender key rotated.
        assert_eq!(result.rotation_result.new_epoch, 1);
        assert!(!result.rotation_result.epoch_advance_message.is_empty());

        // Layer 1: target added to block list.
        assert!(block_list.contains("did:dht:dave"));

        // Layer 2: block notification generated.
        assert!(!result.block_notification.is_empty());

        // Layer 2: destruction event emitted.
        assert_eq!(result.destruction_event.context_id, "ctx-1");
        assert_eq!(result.destruction_event.target_did, did("did:dht:dave"));
        assert_eq!(result.destruction_event.blocker_did, did("did:dht:alice"));

        // Layer 3: access key deletion signaled.
        assert!(result.access_key_deletion_required);

        // Block list event recorded.
        assert!(matches!(
            &result.block_list_event,
            BlockListEvent::BlockDIDInContext { target_did, context_id, .. }
            if *target_did == did("did:dht:dave") && context_id == "ctx-1"
        ));
    }

    #[tokio::test]
    async fn tier1_block_returns_correct_context_id() {
        let (custody, key) = make_custody_and_key().await;
        let mut block_list = HashSet::new();

        let params = BlockInContextParams {
            blocker_did: "did:dht:alice",
            target_did: "did:dht:dave",
            context_id: "ctx-special",
            current_epoch: 5,
            signer_key_ref: SigningKeyId::Active,
        };
        let clock = scp_primitives::SystemClock;
        let result = block_did_in_context(&custody, &key, &params, &mut block_list, &clock)
            .await
            .unwrap();

        assert_eq!(result.context_id, "ctx-special");
        assert_eq!(result.rotation_result.new_epoch, 6);
    }

    #[tokio::test]
    async fn tier1_block_with_agent_key_ref() {
        let (custody, key) = make_custody_and_key().await;
        let mut block_list = HashSet::new();

        // Both Active and Agent signing key refs are valid per ADR-039.
        let params = BlockInContextParams {
            blocker_did: "did:dht:alice",
            target_did: "did:dht:dave",
            context_id: "ctx-1",
            current_epoch: 0,
            signer_key_ref: SigningKeyId::Agent,
        };
        let clock = scp_primitives::SystemClock;
        let result = block_did_in_context(&custody, &key, &params, &mut block_list, &clock).await;

        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Tier 2: block_did_global tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn tier2_block_propagates_to_shared_contexts() {
        let (custody, key) = make_custody_and_key().await;
        let block_list_state = BlockListState::new();
        let mut per_context_block_lists = std::collections::HashMap::new();
        let mut per_context_epochs = std::collections::HashMap::new();
        per_context_epochs.insert("ctx-1".to_owned(), 0u64);
        per_context_epochs.insert("ctx-2".to_owned(), 3u64);

        let shared_contexts = vec!["ctx-1".to_owned(), "ctx-2".to_owned()];

        let params = GlobalBlockParams {
            blocker_did: "did:dht:alice",
            target_did: "did:dht:dave",
            shared_context_ids: &shared_contexts,
            signer_key_ref: SigningKeyId::Active,
        };
        let clock = scp_primitives::SystemClock;
        let result = block_did_global(
            &custody,
            &key,
            &params,
            &block_list_state,
            &mut per_context_block_lists,
            &per_context_epochs,
            &clock,
        )
        .await
        .expect("global block should succeed");

        // Global block event recorded.
        assert!(matches!(
            &result.block_list_event,
            BlockListEvent::BlockDID { target_did, .. }
            if *target_did == did("did:dht:dave")
        ));

        // Both shared contexts had block protocol executed.
        assert_eq!(result.context_results.len(), 2);
        assert_eq!(result.pending_contexts.len(), 0);

        // Each context result has correct context_id.
        let ctx_ids: Vec<&str> = result
            .context_results
            .iter()
            .map(|r| r.context_id.as_str())
            .collect();
        assert!(ctx_ids.contains(&"ctx-1"));
        assert!(ctx_ids.contains(&"ctx-2"));

        // Block lists were updated.
        assert!(per_context_block_lists["ctx-1"].contains("did:dht:dave"));
        assert!(per_context_block_lists["ctx-2"].contains("did:dht:dave"));
    }

    #[tokio::test]
    async fn tier2_block_is_idempotent() {
        let (custody, key) = make_custody_and_key().await;

        // Set up state where Dave is already blocked in ctx-1.
        let mut block_list_state = BlockListState::new();
        block_list_state.apply(&BlockListEvent::BlockDIDInContext {
            target_did: did("did:dht:dave"),
            context_id: "ctx-1".to_owned(),
            timestamp: 1000,
        });

        let mut per_context_block_lists = std::collections::HashMap::new();
        per_context_block_lists.insert(
            "ctx-1".to_owned(),
            HashSet::from(["did:dht:dave".to_owned()]),
        );
        let mut per_context_epochs = std::collections::HashMap::new();
        per_context_epochs.insert("ctx-1".to_owned(), 1u64);
        per_context_epochs.insert("ctx-2".to_owned(), 0u64);

        let shared_contexts = vec!["ctx-1".to_owned(), "ctx-2".to_owned()];

        let params = GlobalBlockParams {
            blocker_did: "did:dht:alice",
            target_did: "did:dht:dave",
            shared_context_ids: &shared_contexts,
            signer_key_ref: SigningKeyId::Active,
        };
        let clock = scp_primitives::SystemClock;
        let result = block_did_global(
            &custody,
            &key,
            &params,
            &block_list_state,
            &mut per_context_block_lists,
            &per_context_epochs,
            &clock,
        )
        .await
        .unwrap();

        // ctx-1 was skipped (already blocked), ctx-2 was executed.
        assert_eq!(result.context_results.len(), 1);
        assert_eq!(result.context_results[0].context_id, "ctx-2");
    }

    #[tokio::test]
    async fn tier2_block_with_no_shared_contexts() {
        let (custody, key) = make_custody_and_key().await;
        let block_list_state = BlockListState::new();
        let mut per_context_block_lists = std::collections::HashMap::new();
        let per_context_epochs = std::collections::HashMap::new();

        let params = GlobalBlockParams {
            blocker_did: "did:dht:alice",
            target_did: "did:dht:dave",
            shared_context_ids: &[],
            signer_key_ref: SigningKeyId::Active,
        };
        let clock = scp_primitives::SystemClock;
        let result = block_did_global(
            &custody,
            &key,
            &params,
            &block_list_state,
            &mut per_context_block_lists,
            &per_context_epochs,
            &clock,
        )
        .await
        .unwrap();

        // Global event still recorded.
        assert!(matches!(
            &result.block_list_event,
            BlockListEvent::BlockDID { .. }
        ));

        // No context results, no pending.
        assert!(result.context_results.is_empty());
        assert!(result.pending_contexts.is_empty());
    }

    #[tokio::test]
    async fn tier2_idempotent_repeated_global_block() {
        // If all shared contexts are already blocked, the global block
        // still succeeds with zero context results.
        let (custody, key) = make_custody_and_key().await;

        let mut block_list_state = BlockListState::new();
        block_list_state.apply(&BlockListEvent::BlockDIDInContext {
            target_did: did("did:dht:dave"),
            context_id: "ctx-1".to_owned(),
            timestamp: 1000,
        });
        block_list_state.apply(&BlockListEvent::BlockDIDInContext {
            target_did: did("did:dht:dave"),
            context_id: "ctx-2".to_owned(),
            timestamp: 2000,
        });

        let mut per_context_block_lists = std::collections::HashMap::new();
        let per_context_epochs = std::collections::HashMap::new();

        let shared_contexts = vec!["ctx-1".to_owned(), "ctx-2".to_owned()];

        let params = GlobalBlockParams {
            blocker_did: "did:dht:alice",
            target_did: "did:dht:dave",
            shared_context_ids: &shared_contexts,
            signer_key_ref: SigningKeyId::Active,
        };
        let clock = scp_primitives::SystemClock;
        let result = block_did_global(
            &custody,
            &key,
            &params,
            &block_list_state,
            &mut per_context_block_lists,
            &per_context_epochs,
            &clock,
        )
        .await
        .unwrap();

        // All contexts skipped (idempotent).
        assert_eq!(result.context_results.len(), 0);
        assert!(result.pending_contexts.is_empty());
    }

    // -----------------------------------------------------------------------
    // process_received_block_notification tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn received_block_rotates_target_sender_key() {
        let (custody, key) = make_custody_and_key().await;
        let mut block_list = HashSet::new();

        let params = ReceivedBlockParams {
            target_did: "did:dht:dave",   // target (Dave was blocked)
            blocker_did: "did:dht:alice", // blocker
            context_id: "ctx-1",
            current_epoch: 0,
            signer_key_ref: SigningKeyId::Active,
        };
        let clock = scp_primitives::SystemClock;
        let result =
            process_received_block_notification(&custody, &key, &params, &mut block_list, &clock)
                .await
                .unwrap();

        // Target's sender key was rotated.
        assert_eq!(result.rotation_result.new_epoch, 1);
        assert!(!result.rotation_result.epoch_advance_message.is_empty());

        // Blocker was added to target's block list.
        assert!(block_list.contains("did:dht:alice"));

        // Destruction event emitted for the blocker's cached material.
        assert_eq!(result.destruction_event.context_id, "ctx-1");
        assert_eq!(result.destruction_event.target_did, did("did:dht:alice"));

        // Access key deletion required.
        assert!(result.access_key_deletion_required);
    }

    // -----------------------------------------------------------------------
    // is_block_effective tests
    // -----------------------------------------------------------------------

    #[test]
    fn is_block_effective_per_context() {
        let mut state = BlockListState::new();
        state.apply(&BlockListEvent::BlockDIDInContext {
            target_did: did("did:dht:dave"),
            context_id: "ctx-1".to_owned(),
            timestamp: 1000,
        });

        assert!(is_block_effective(&state, &did("did:dht:dave"), "ctx-1"));
        assert!(!is_block_effective(&state, &did("did:dht:dave"), "ctx-2"));
    }

    #[test]
    fn is_block_effective_global() {
        let mut state = BlockListState::new();
        state.apply(&BlockListEvent::BlockDID {
            target_did: did("did:dht:dave"),
            timestamp: 1000,
        });

        // Globally blocked = effective in ALL contexts.
        assert!(is_block_effective(&state, &did("did:dht:dave"), "ctx-1"));
        assert!(is_block_effective(&state, &did("did:dht:dave"), "ctx-2"));
        assert!(is_block_effective(&state, &did("did:dht:dave"), "ctx-any"));
    }

    #[test]
    fn is_block_effective_neither() {
        let state = BlockListState::new();
        assert!(!is_block_effective(&state, &did("did:dht:dave"), "ctx-1"));
    }

    #[test]
    fn is_block_effective_both_tiers() {
        let mut state = BlockListState::new();
        state.apply(&BlockListEvent::BlockDID {
            target_did: did("did:dht:dave"),
            timestamp: 1000,
        });
        state.apply(&BlockListEvent::BlockDIDInContext {
            target_did: did("did:dht:dave"),
            context_id: "ctx-1".to_owned(),
            timestamp: 2000,
        });

        // Both tiers active — still effective.
        assert!(is_block_effective(&state, &did("did:dht:dave"), "ctx-1"));
    }

    // -----------------------------------------------------------------------
    // StateDestructionEvent serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn state_destruction_event_serialization_roundtrip() {
        let event = StateDestructionEvent {
            context_id: "ctx-1".to_owned(),
            target_did: did("did:dht:dave"),
            blocker_did: did("did:dht:alice"),
            timestamp: 1_700_000_000_000,
        };

        let bytes = serde_json::to_vec(&event).unwrap();
        let decoded: StateDestructionEvent = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn state_destruction_event_msgpack_roundtrip() {
        let event = StateDestructionEvent {
            context_id: "ctx-1".to_owned(),
            target_did: did("did:dht:dave"),
            blocker_did: did("did:dht:alice"),
            timestamp: 1_700_000_000_000,
        };

        let bytes = rmp_serde::to_vec(&event).unwrap();
        let decoded: StateDestructionEvent = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, event);
    }
}
