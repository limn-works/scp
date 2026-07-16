//! MLS encrypt/decrypt operations for SCP.
//!
//! This module provides application message encryption and decryption on top
//! of the [`ScpMlsGroup`] wrapper. All cryptographic guarantees — membership
//! tag verification, generation number tracking (replay prevention), and
//! forward secrecy — are enforced by `OpenMLS` internally.
//!
//! # Operations
//!
//! - [`encrypt`] — Encrypt plaintext as an MLS `PrivateMessage` (application message).
//! - [`decrypt`] — Decrypt an MLS `PrivateMessage`, verifying membership and replay protection.
//!
//! # Security Properties
//!
//! - **Membership tag (spec §9.8.1):** Every ciphertext carries an HMAC proving
//!   the sender holds the current epoch's group secrets. `process_message` verifies
//!   this tag before returning the plaintext.
//! - **Generation number (spec §9.8.2):** MLS assigns a monotonically increasing
//!   generation number to each sender's application messages within an epoch.
//!   `process_message` rejects any message whose generation number has already been
//!   seen for that sender, preventing replay attacks.
//!
//! See ADR-001 acceptance criteria 4 and 5.

use std::panic::{AssertUnwindSafe, catch_unwind};

use openmls::prelude::*;
use scp_clock::Clock;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use crate::convergent_timestamp::decode_convergent_timestamp_aad;
use crate::error::MlsError;
use crate::group::ScpMlsGroup;
use crate::lifetime::validate_key_package_lifetime;
use crate::wrapping_extension::extract_wrapping_key;

/// The result of decrypting an MLS protocol message.
///
/// MLS messages are not limited to application data — they may also be Commits
/// (epoch changes) or Proposals (deferred operations cached by `OpenMLS`). This
/// enum allows callers to distinguish message types and handle each correctly:
///
/// - `Application` — user-generated plaintext with a sender DID.
/// - `Commit` — epoch advancement; the group has been updated via
///   `merge_staged_commit`. No plaintext is produced.
/// - `Proposal` — a deferred operation cached by `OpenMLS` during
///   `process_message`. No plaintext is produced.
///
/// Callers that only expect application messages should match on `Application`
/// and treat `Commit`/`Proposal` as control messages (no user payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptedContent {
    /// An application message carrying user plaintext.
    Application {
        /// The decrypted payload bytes.
        plaintext: Vec<u8>,
        /// The sender's DID string extracted from the MLS credential.
        sender_did: String,
    },
    /// A Commit message that advanced the MLS group epoch.
    /// `merge_staged_commit` has already been called.
    Commit {
        /// The sender's DID string extracted from the MLS credential.
        sender_did: String,
    },
    /// A Proposal message cached by `OpenMLS` during `process_message`.
    /// No explicit merge is needed — `OpenMLS` caches proposals automatically.
    Proposal {
        /// The sender's DID string extracted from the MLS credential.
        sender_did: String,
    },
}

/// Encrypts plaintext as an MLS `PrivateMessage` (application message).
///
/// The returned [`MlsMessageOut`] is a fully encrypted MLS message that
/// includes:
/// - AES-128-GCM encryption of the plaintext
/// - A membership tag HMAC proving the sender holds the current epoch secrets
/// - An automatically assigned generation number for replay prevention
///
/// # Arguments
///
/// * `group` - The MLS group to encrypt within. Must be active.
/// * `plaintext` - The plaintext bytes to encrypt.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::EncryptionFailed`] if `OpenMLS` encryption fails
/// (e.g., pending proposals exist, or the member has been evicted).
///
/// See ADR-001 acceptance criterion 4.
pub fn encrypt(group: &mut ScpMlsGroup, plaintext: &[u8]) -> Result<MlsMessageOut, MlsError> {
    let signer = group.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;

    g.create_message(&group.provider, signer, plaintext)
        .map_err(|e| MlsError::EncryptionFailed(e.to_string()))
}

/// Decrypts an MLS `PrivateMessage` and returns the plaintext bytes.
///
/// The decryption process verifies:
/// - **Membership tag (spec §9.8.1):** The sender's HMAC is checked against
///   the current epoch secrets. If the sender does not hold valid group secrets,
///   decryption fails.
/// - **Generation number (spec §9.8.2):** The message's generation number is
///   checked against the highest seen for this sender in this epoch. If the
///   generation number has already been consumed (replay), decryption fails.
///
/// # Arguments
///
/// * `group` - The MLS group to decrypt within. Must be active.
/// * `ciphertext` - The serialized MLS ciphertext bytes (TLS-serialized
///   `MlsMessageOut` from the sender).
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::DecryptionFailed`] if the ciphertext cannot be
/// deserialized, the membership tag is invalid, the generation number
/// indicates a replay, or the message is malformed.
/// Returns [`MlsError::NotApplicationMessage`] if the decrypted message
/// is not an application message (e.g., it is a commit or proposal).
///
/// See ADR-001 acceptance criterion 5.
pub fn decrypt(group: &mut ScpMlsGroup, ciphertext: &[u8]) -> Result<Vec<u8>, MlsError> {
    if group.group.is_none() {
        return Err(MlsError::GroupDestroyed);
    }

    // Deserialize the ciphertext bytes into an MlsMessageIn.
    let message_in = MlsMessageIn::tls_deserialize(&mut &*ciphertext)
        .map_err(|e| MlsError::DecryptionFailed(format!("deserializing ciphertext: {e}")))?;

    // Convert to a ProtocolMessage for processing.
    let protocol_message = message_in
        .try_into_protocol_message()
        .map_err(|e| MlsError::DecryptionFailed(format!("extracting protocol message: {e}")))?;

    // Process the message — this verifies membership tag and generation number.
    //
    // In a DEBUG/native build, OpenMLS's decrypt path can panic on AEAD
    // decryption failure for a tampered ciphertext (e.g. a corrupted
    // authentication tag): the panic is an openmls `debug_assert!`
    // ("Ciphertext decryption failed",
    // openmls-0.8.1/src/framing/private_message_in.rs). We guard against it with
    // `catch_unwind`, converting the panic into an `MlsError::DecryptionFailed`
    // so a malicious relay cannot crash a native client process (DoS).
    //
    // NOTE (ADR-057 §Prereq-4): the LOAD-BEARING fail-closed guarantee is NOT
    // this `catch_unwind` — it is the `--release` build. That openmls panic is a
    // `debug_assert!`, so it is COMPILED OUT of release builds; a shipped
    // `--release` client (native cdylib and the browser `wasm-pack build
    // --release` artifact alike) gets a typed `Err` from `process_message` on
    // tampered/malformed ciphertext, which becomes `MlsError::DecryptionFailed`
    // (browser: `[SCP-CRYPTO-4010]`). Pinned by `[profile.release]
    // debug-assertions = false` (root `Cargo.toml`) plus the decrypt-path fuzz
    // target `fuzz/fuzz_targets/fuzz_mls_decrypt.rs`; the browser SDK MUST build
    // `--release` (a `--dev` build would re-arm the `debug_assert`). This
    // `catch_unwind` remains as DEFENSE-IN-DEPTH for native/debug builds (where
    // the assert can fire) and is a harmless no-op on the release wasm path
    // (wasm `panic=abort`, so nothing to catch — and nothing panics in release
    // anyway). It is NOT relied upon for the browser guarantee. This applies to
    // every `catch_unwind` site in this file.
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    let process_result = catch_unwind(AssertUnwindSafe(|| {
        g.process_message(&group.provider, protocol_message)
    }));

    let processed = match process_result {
        Ok(Ok(msg)) => msg,
        Ok(Err(e)) => return Err(MlsError::DecryptionFailed(e.to_string())),
        Err(_) => {
            return Err(MlsError::DecryptionFailed(
                "OpenMLS panicked during message processing".to_string(),
            ));
        }
    };

    // Extract the application message content.
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(app_msg.into_bytes()),
        _ => Err(MlsError::NotApplicationMessage),
    }
}

/// Decrypts an MLS `PrivateMessage` and returns both the plaintext bytes and
/// the sender's Ed25519 signature key (as extracted from the MLS group state).
///
/// This function performs the same decryption as [`decrypt`] but additionally
/// resolves the sender's identity from the MLS group tree. The sender's
/// `signature_key` from their leaf node is returned alongside the plaintext,
/// enabling the caller to verify inner envelope signatures without requiring
/// the sender's public key as an external parameter.
///
/// # Arguments
///
/// * `group` - The MLS group to decrypt within. Must be active.
/// * `ciphertext` - The serialized MLS ciphertext bytes.
///
/// # Returns
///
/// A tuple of `(plaintext, sender_signature_key)` where `sender_signature_key`
/// is the Ed25519 public key bytes from the sender's MLS leaf node.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::DecryptionFailed`] if decryption or sender resolution
/// fails.
/// Returns [`MlsError::NotApplicationMessage`] if the decrypted message is
/// not an application message.
///
/// See SCP-177: resolve sender key internally in `open_envelope`.
pub fn decrypt_with_sender_key(
    group: &mut ScpMlsGroup,
    ciphertext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), MlsError> {
    if group.group.is_none() {
        return Err(MlsError::GroupDestroyed);
    }

    // Deserialize the ciphertext bytes into an MlsMessageIn.
    let message_in = MlsMessageIn::tls_deserialize(&mut &*ciphertext)
        .map_err(|e| MlsError::DecryptionFailed(format!("deserializing ciphertext: {e}")))?;

    // Convert to a ProtocolMessage for processing.
    let protocol_message = message_in
        .try_into_protocol_message()
        .map_err(|e| MlsError::DecryptionFailed(format!("extracting protocol message: {e}")))?;

    // Process the message — this verifies membership tag and generation number.
    //
    // Debug/native-only openmls decrypt `debug_assert!` panic on a tampered
    // ciphertext; guarded with catch_unwind (same as in `decrypt`).
    // NOTE (ADR-057 §Prereq-4): the load-bearing fail-closed guarantee is the
    // `--release` build (the assert is compiled out → typed `Err`); this
    // catch_unwind is defense-in-depth for native/debug builds, a no-op on the
    // release wasm path. See the full note on the `decrypt` site above.
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    let process_result = catch_unwind(AssertUnwindSafe(|| {
        g.process_message(&group.provider, protocol_message)
    }));

    let processed = match process_result {
        Ok(Ok(msg)) => msg,
        Ok(Err(e)) => return Err(MlsError::DecryptionFailed(e.to_string())),
        Err(_) => {
            return Err(MlsError::DecryptionFailed(
                "OpenMLS panicked during message processing".to_string(),
            ));
        }
    };

    // Extract the sender's leaf index from the ProcessedMessage before
    // consuming it with into_content().
    let sender = processed.sender().clone();
    let Sender::Member(sender_leaf_index) = sender else {
        return Err(MlsError::DecryptionFailed(
            "sender is not a group member".to_string(),
        ));
    };

    // Look up the sender's signature key from the group member list.
    let g = group.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
    let sender_signature_key = g
        .members()
        .find(|m| m.index == sender_leaf_index)
        .map(|m| m.signature_key)
        .ok_or_else(|| {
            MlsError::DecryptionFailed(format!(
                "sender leaf index {sender_leaf_index:?} not found in group members"
            ))
        })?;

    // Extract the application message content.
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            Ok((app_msg.into_bytes(), sender_signature_key))
        }
        _ => Err(MlsError::NotApplicationMessage),
    }
}

/// Decrypts an MLS `PrivateMessage` and returns a [`DecryptedContent`] enum
/// distinguishing application messages, commits, and proposals.
///
/// This function resolves the sender's identity by parsing the `ScpCredential`
/// from the `BasicCredential` embedded in the sender's leaf node. This is the
/// key primitive for the receive bridge: the caller gets both the decrypted
/// content and the DID of the sender without any out-of-band lookup.
///
/// # Message Type Handling
///
/// - **`ApplicationMessage`** — returns `DecryptedContent::Application` with
///   the plaintext and sender DID.
/// - **`StagedCommitMessage`** — calls `merge_staged_commit` to apply the
///   epoch change (preventing MLS group corruption), then returns
///   `DecryptedContent::Commit` with the sender DID.
/// - **`ProposalMessage` / `ExternalJoinProposalMessage`** — proposals are
///   cached by `OpenMLS` during `process_message` automatically. Returns
///   `DecryptedContent::Proposal` with the sender DID.
///
/// # Arguments
///
/// * `group` - The MLS group to decrypt within. Must be active.
/// * `ciphertext` - The serialized MLS ciphertext bytes.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::DecryptionFailed`] if decryption or sender resolution
/// fails (including credential parsing failure).
/// Returns [`MlsError::CommitProcessingFailed`] if a staged commit cannot be
/// merged after processing.
/// Returns [`MlsError::KeyPackageLifetimeInvalid`] if a Commit's Add proposal
/// carries a `KeyPackage` whose `Lifetime` fails validation against the injected
/// clock; the staged commit is dropped **without merging** (ADR-057 §Prereq-1).
///
/// # Arguments
///
/// * `clock` - The injected hardened [`Clock`]. For a Commit, each Add
///   proposal's `KeyPackage` `Lifetime` is re-validated against it *before*
///   `merge_staged_commit`, so an add carrying a forged/expired lifetime is
///   rejected pre-merge — the openmls internal `Lifetime::is_valid` that ran
///   during `process_message` is on the un-injectable (wasm: unhardened) clock.
pub fn decrypt_with_sender_did(
    group: &mut ScpMlsGroup,
    ciphertext: &[u8],
    clock: &dyn Clock,
) -> Result<DecryptedContent, MlsError> {
    if group.group.is_none() {
        return Err(MlsError::GroupDestroyed);
    }

    let message_in = MlsMessageIn::tls_deserialize(&mut &*ciphertext)
        .map_err(|e| MlsError::DecryptionFailed(format!("deserializing ciphertext: {e}")))?;

    let protocol_message = message_in
        .try_into_protocol_message()
        .map_err(|e| MlsError::DecryptionFailed(format!("extracting protocol message: {e}")))?;

    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    // NOTE (ADR-057 §Prereq-4): the load-bearing fail-closed guarantee is the
    // `--release` build (openmls's decrypt `debug_assert!` is compiled out →
    // typed `Err`); this catch_unwind is defense-in-depth for native/debug
    // builds, a harmless no-op on the release wasm path. See the full note on
    // the `decrypt` site above.
    let process_result = catch_unwind(AssertUnwindSafe(|| {
        g.process_message(&group.provider, protocol_message)
    }));

    let processed = match process_result {
        Ok(Ok(msg)) => msg,
        Ok(Err(e)) => return Err(MlsError::DecryptionFailed(e.to_string())),
        Err(_) => {
            return Err(MlsError::DecryptionFailed(
                "OpenMLS panicked during message processing".to_string(),
            ));
        }
    };

    // Extract the sender's leaf index before consuming the ProcessedMessage.
    let sender = processed.sender().clone();
    let Sender::Member(sender_leaf_index) = sender else {
        return Err(MlsError::DecryptionFailed(
            "sender is not a group member".to_string(),
        ));
    };

    // Look up the sender's credential from the group member list and parse
    // the SCP credential to extract the DID.
    let g = group.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
    let sender_credential = g
        .members()
        .find(|m| m.index == sender_leaf_index)
        .map(|m| m.credential)
        .ok_or_else(|| {
            MlsError::DecryptionFailed(format!(
                "sender leaf index {sender_leaf_index:?} not found in group members"
            ))
        })?;
    let sender_did = credential_to_did(&sender_credential)?;

    // Dispatch based on the processed message content type.
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(DecryptedContent::Application {
            plaintext: app_msg.into_bytes(),
            sender_did,
        }),
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            // SECURITY (ADR-057 §Prereq-1): re-validate each Add proposal's
            // KeyPackage `Lifetime` against the injected hardened clock BEFORE
            // merging. openmls validated these lifetimes during
            // `process_message` against its own un-injectable (wasm: unhardened)
            // clock; this bracket adds the hardened check + the RFC 9420
            // max-range bound. On failure we return WITHOUT merging, so the
            // group stays on its current epoch (fail-closed, not half-applied) —
            // the same shape as the Remove-refusal in
            // `decrypt_with_membership_changes`.
            for add in staged_commit.add_proposals() {
                validate_key_package_lifetime(add.add_proposal().key_package().life_time(), clock)?;
            }

            // Merge the staged commit to advance the group epoch. Without
            // this call, process_message has consumed the message but the
            // group state is not updated, corrupting the MLS group.
            let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
            g.merge_staged_commit(&group.provider, *staged_commit)
                .map_err(|e| {
                    MlsError::CommitProcessingFailed(format!("merging staged commit: {e}"))
                })?;
            Ok(DecryptedContent::Commit { sender_did })
        }
        ProcessedMessageContent::ProposalMessage(_)
        | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
            // Proposals are cached by OpenMLS automatically during
            // process_message — no explicit action needed.
            Ok(DecryptedContent::Proposal { sender_did })
        }
    }
}

/// The membership changes an existing member observes when it processes an
/// inbound MLS message.
///
/// Returned by [`decrypt_with_membership_changes`]. For an application message
/// the change is [`InboundChange::Application`]. For an **add-only** Commit the
/// change is [`InboundChange::Commit`], carrying the DIDs added by the Commit's
/// Add proposals — recovered from the staged commit *before* it is merged, then
/// merged — so an existing member can mirror the committer's membership-leaf
/// appends and converge. For a Commit that carries any **Remove** proposal the
/// change is [`InboundChange::UnsupportedMembershipChange`]: the staged commit
/// is dropped **without merging**, so the MLS group stays on its current epoch
/// and remains consistent with the caller's SCP-layer state (fail-closed, not
/// half-applied). For a bare Proposal the change is [`InboundChange::Proposal`].
#[derive(Clone, PartialEq, Eq)]
pub enum InboundChange {
    /// An application message carrying user plaintext and the sender DID.
    ///
    /// Application messages are **not** convergent event-log leaves (ADR-011
    /// exclusion taxonomy §2: `MessageSent` is per-author with no total delivery
    /// order — see `.docs/adrs/phase-2.md`), so they bind no convergent
    /// timestamp: they are plain-encrypted and carry no AAD. The receiver records
    /// the message as local history, not as a Merkle leaf.
    Application {
        /// The decrypted payload bytes.
        plaintext: Vec<u8>,
        /// The sender's DID string extracted from the MLS credential.
        sender_did: String,
    },
    /// A Commit that advanced the group epoch. `merge_staged_commit` has already
    /// been called. `added_dids` are the SCP DIDs of the members the Commit's Add
    /// proposals add, recovered from the staged commit's Add proposals'
    /// `KeyPackage` leaf credentials before the merge.
    ///
    /// A Commit carrying any Remove proposal never reaches this variant — it is
    /// surfaced as [`InboundChange::UnsupportedMembershipChange`] *without*
    /// merging, so this variant only ever describes an applied add-only or no-add
    /// epoch advance.
    Commit {
        /// The committer's DID string extracted from the MLS credential.
        sender_did: String,
        /// DIDs added by this Commit's Add proposals, in proposal order. Empty
        /// for a no-add Commit (e.g. a self-update).
        added_dids: Vec<String>,
        /// The `scp_wrapping_key` X25519 public keys of the members this Commit's
        /// Add proposals add, in the SAME proposal order as `added_dids` (so
        /// `added_wrapping_keys[i]` is the wrapping key published by the member
        /// named in `added_dids[i]`). Recovered from each Add proposal's
        /// `KeyPackage` leaf extension BEFORE the merge (§9.16.1, ADR-057).
        ///
        /// FAIL-CLOSED (ADR-057 sender-key distribution INVARIANT 3): an Add whose
        /// `KeyPackage` leaf carries no `scp_wrapping_key` extension is **rejected
        /// pre-merge** (the whole Commit is dropped without merging, leaving the
        /// group on its current epoch), because admitting a member no peer can
        /// HPKE-seal a sender key to would silently break §9.16 distribution. This
        /// vector is therefore always exactly as long as `added_dids`; it is empty
        /// only for a no-add Commit.
        added_wrapping_keys: Vec<[u8; 32]>,
        /// The authenticated convergent committer timestamp (Unix seconds),
        /// recovered from the Commit's verified MLS AAD *before* the merge and
        /// adopted **verbatim** (ADR-057). The receiver stamps this exact value
        /// on each mirrored `MemberJoined` leaf. `Some` only when the Commit adds
        /// members (an add-Commit stamps membership leaves); `None` for a no-add
        /// Commit, which stamps no leaf and so carries no timestamp.
        committer_timestamp_secs: Option<u64>,
    },
    /// A Commit that carries one or more Remove proposals, which this seam does
    /// not converge.
    ///
    /// The staged commit was **dropped without merging**: the MLS group is left
    /// on its current (pre-Commit) epoch, so MLS state and the caller's
    /// SCP-layer state remain mutually consistent (pre-remove) rather than
    /// half-advanced. The caller maps this to a fail-closed error; the group
    /// stays usable on the old epoch.
    ///
    /// `removed_dids` are the SCP DIDs the Remove proposals would have evicted,
    /// recovered from the *current* (pre-merge) group tree, so the caller can
    /// report which members the rejected Commit targeted.
    UnsupportedMembershipChange {
        /// The committer's DID string extracted from the MLS credential.
        sender_did: String,
        /// DIDs the rejected Commit's Remove proposals would evict, in proposal
        /// order, read from the pre-merge tree.
        removed_dids: Vec<String>,
    },
    /// A Proposal cached by `OpenMLS` during `process_message`. No plaintext and
    /// no committed membership change yet.
    Proposal {
        /// The sender's DID string extracted from the MLS credential.
        sender_did: String,
    },
}

impl std::fmt::Debug for InboundChange {
    /// Manual `Debug` that REDACTS the decrypted plaintext.
    ///
    /// Per ADR-057 the tab boundary is the plaintext boundary: a
    /// `{:?}`-formatted [`InboundChange::Application`] must never leak the
    /// recovered cleartext into logs, panics, or test output. Only the byte
    /// length is printed; the control variants forward their (non-secret)
    /// fields.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Application {
                plaintext,
                sender_did,
            } => f
                .debug_struct("Application")
                .field(
                    "plaintext",
                    &format_args!("<redacted {} bytes>", plaintext.len()),
                )
                .field("sender_did", sender_did)
                .finish(),
            Self::Commit {
                sender_did,
                added_dids,
                added_wrapping_keys,
                committer_timestamp_secs,
            } => f
                .debug_struct("Commit")
                .field("sender_did", sender_did)
                .field("added_dids", added_dids)
                // Wrapping public keys are not secret, but they are noise in a
                // log; print only the count so Debug stays legible.
                .field(
                    "added_wrapping_keys",
                    &format_args!("[{} keys]", added_wrapping_keys.len()),
                )
                .field("committer_timestamp_secs", committer_timestamp_secs)
                .finish(),
            Self::UnsupportedMembershipChange {
                sender_did,
                removed_dids,
            } => f
                .debug_struct("UnsupportedMembershipChange")
                .field("sender_did", sender_did)
                .field("removed_dids", removed_dids)
                .finish(),
            Self::Proposal { sender_did } => f
                .debug_struct("Proposal")
                .field("sender_did", sender_did)
                .finish(),
        }
    }
}

/// Parses the SCP DID out of an MLS [`Credential`] (a `BasicCredential` whose
/// identity payload is a `MessagePack`-encoded [`crate::credential::ScpCredential`]).
///
/// Shared by the sender-resolution paths and the membership-change recovery in
/// [`decrypt_with_membership_changes`], so every place that names a member from
/// an MLS leaf parses the credential identically.
fn credential_to_did(credential: &Credential) -> Result<String, MlsError> {
    let basic = BasicCredential::try_from(credential.clone())
        .map_err(|e| MlsError::DecryptionFailed(format!("extracting BasicCredential: {e}")))?;
    let scp_cred = crate::credential::ScpCredential::from_bytes(basic.identity())
        .map_err(|e| MlsError::DecryptionFailed(format!("parsing ScpCredential: {e}")))?;
    Ok(scp_cred.did)
}

/// Recovers, pre-merge, the DID and published `scp_wrapping_key` of every member
/// a staged Commit's Add proposals add, in proposal order (so the two returned
/// vectors are index-aligned and equal-length).
///
/// Each Add proposal's `KeyPackage` was already validated by `process_message`,
/// so its DID is cryptographically authenticated. This pass additionally
/// re-validates the `KeyPackage` `Lifetime` against the injected hardened clock
/// (ADR-057 §Prereq-1) and enforces the sender-key-distribution fail-closed
/// requirement (INVARIANT 3): a leaf carrying no `scp_wrapping_key` extension is
/// rejected via `?`, so the caller drops the staged commit unmerged and the group
/// stays on its current epoch. A member no peer can HPKE-seal a sender key to must
/// never be admitted.
///
/// # Errors
///
/// Returns [`MlsError::KeyPackageLifetimeInvalid`] if an Add proposal's
/// `Lifetime` fails hardened-clock validation, [`MlsError::ExtensionError`] if a
/// leaf carries no `scp_wrapping_key` extension, or a credential-parse error.
fn recover_added_members_pre_merge(
    staged_commit: &StagedCommit,
    clock: &dyn Clock,
) -> Result<(Vec<String>, Vec<[u8; 32]>), MlsError> {
    let mut added_dids = Vec::new();
    let mut added_wrapping_keys = Vec::new();
    for add in staged_commit.add_proposals() {
        let key_package = add.add_proposal().key_package();
        validate_key_package_lifetime(key_package.life_time(), clock)?;
        added_dids.push(credential_to_did(key_package.leaf_node().credential())?);
        let wrapping_key =
            extract_wrapping_key(key_package.leaf_node().extensions())?.ok_or_else(|| {
                MlsError::ExtensionError(
                    "add rejected pre-merge: KeyPackage leaf carries no \
                     scp_wrapping_key extension; a member no peer can HPKE-seal \
                     a sender key to must not be admitted (§9.16.1, ADR-057 \
                     sender-key distribution INVARIANT 3)"
                        .to_owned(),
                )
            })?;
        added_wrapping_keys.push(wrapping_key);
    }
    Ok((added_dids, added_wrapping_keys))
}

/// Decrypts an inbound MLS message and, for a Commit, surfaces the membership
/// changes it carries so an existing member can converge its SCP-layer state.
///
/// This is the existing-member counterpart of the joiner's
/// [`crate::group::add_member`] path: the committer (adder) appends a
/// `MemberJoined` event-log leaf and hands the new member the full log, while
/// **existing** members learn of the add only by processing the Commit. To
/// append the identical convergent membership leaf, an existing member needs
/// the added member's DID — which [`decrypt_with_sender_did`] discarded. This
/// function recovers it.
///
/// # Convergent timestamp authentication (ADR-057)
///
/// Only an **add-Commit** stamps convergent membership (`MemberJoined`) leaves,
/// so only it binds a convergent committer timestamp. This function recovers the
/// **authenticated** value from openmls's *verified* `ProcessedMessage::aad()`
/// (the `FramedContent.authenticated_data`, covered by the committer's leaf
/// signature and the `PrivateMessage` AEAD tag), bound at commit time by
/// [`crate::group::add_member_with_convergent_timestamp`], and adopts it
/// **verbatim** — there is no receiver-side plausibility window and no clock
/// verdict (a per-receiver verdict would itself be a §9.9.3 violation; see the
/// [`crate::convergent_timestamp`] module docs). Because the value is
/// authenticated, a receiver stamps it on each mirrored `MemberJoined` leaf
/// rather than trusting a loose transported `u64` a relay could forge. A missing
/// or malformed AAD on an add-Commit fails it closed (see Errors).
///
/// Application messages are **not** convergent leaves (ADR-011 exclusion
/// taxonomy §2), so they carry no AAD and no timestamp is decoded for them.
///
/// # Message Type Handling
///
/// - **`ApplicationMessage`** → [`InboundChange::Application`] (plaintext +
///   sender DID). No AAD is read; the message is local history, not a leaf.
/// - **`StagedCommitMessage`, add-only** → the added members' DIDs are read
///   from the Add proposals' `KeyPackage` leaf credentials **before**
///   `merge_staged_commit`. The pre-merge order is: Remove-refusal → `Lifetime`
///   brackets + added-DID recovery → AAD decode (adopt verbatim) → merge. Any
///   failure drops the staged commit unmerged (epoch unchanged). On success
///   [`InboundChange::Commit`] carries the added DIDs and `Some` authenticated
///   `committer_timestamp_secs`.
/// - **`StagedCommitMessage`, no-add** (e.g. a self-update) → no AAD is decoded
///   (a no-add Commit stamps no membership leaf); [`InboundChange::Commit`] is
///   returned with empty `added_dids` and `committer_timestamp_secs` = `None`,
///   and the epoch advances.
/// - **`StagedCommitMessage` carrying any Remove** → the staged commit is
///   **dropped without merging** and [`InboundChange::UnsupportedMembershipChange`]
///   is returned. The removed members' DIDs are recovered from the *current*
///   (pre-merge) tree for reporting; `merge_staged_commit` is **never called**,
///   so the group stays on its current epoch, consistent with the caller's
///   SCP-layer state.
/// - **`ProposalMessage` / `ExternalJoinProposalMessage`** →
///   [`InboundChange::Proposal`]; `OpenMLS` caches the proposal, no membership
///   change is committed yet, and the AAD is ignored.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed,
/// [`MlsError::DecryptionFailed`] if decryption or credential parsing fails, or
/// [`MlsError::CommitProcessingFailed`] if a staged commit cannot be merged. A
/// Remove-bearing Commit does not error here — it is surfaced as
/// [`InboundChange::UnsupportedMembershipChange`] without merging, leaving the
/// group consistent.
/// Returns [`MlsError::KeyPackageLifetimeInvalid`] if an add-Commit's Add
/// proposal carries a `KeyPackage` whose `Lifetime` fails validation against the
/// injected clock; the staged commit is dropped **without merging** (ADR-057
/// §Prereq-1).
/// Returns [`MlsError::ConvergentTimestampMissing`] /
/// [`MlsError::ConvergentTimestampMalformed`] (ADR-057) if an add-Commit's AAD
/// carries no timestamp or a malformed one. These are raised *pre-merge*, so the
/// epoch is unchanged.
///
/// # Arguments
///
/// * `clock` - The injected hardened [`Clock`]. For an add-Commit, each Add
///   proposal's `KeyPackage` `Lifetime` is re-validated against it *before*
///   `merge_staged_commit`, mirroring the openmls-independent hardening in
///   [`decrypt_with_sender_did`] and [`crate::group::add_member`]. It is no
///   longer used to adjudicate the convergent timestamp (which is adopted
///   verbatim).
pub fn decrypt_with_membership_changes(
    group: &mut ScpMlsGroup,
    ciphertext: &[u8],
    clock: &dyn Clock,
) -> Result<InboundChange, MlsError> {
    if group.group.is_none() {
        return Err(MlsError::GroupDestroyed);
    }

    let message_in = MlsMessageIn::tls_deserialize(&mut &*ciphertext)
        .map_err(|e| MlsError::DecryptionFailed(format!("deserializing ciphertext: {e}")))?;

    let protocol_message = message_in
        .try_into_protocol_message()
        .map_err(|e| MlsError::DecryptionFailed(format!("extracting protocol message: {e}")))?;

    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    // NOTE (ADR-057 §Prereq-4): the load-bearing fail-closed guarantee is the
    // `--release` build (openmls's decrypt `debug_assert!` is compiled out →
    // typed `Err`); this catch_unwind is defense-in-depth for native/debug
    // builds, a harmless no-op on the release wasm path. See the full note on
    // the `decrypt` site above.
    let process_result = catch_unwind(AssertUnwindSafe(|| {
        g.process_message(&group.provider, protocol_message)
    }));

    let processed = match process_result {
        Ok(Ok(msg)) => msg,
        Ok(Err(e)) => return Err(MlsError::DecryptionFailed(e.to_string())),
        Err(_) => {
            return Err(MlsError::DecryptionFailed(
                "OpenMLS panicked during message processing".to_string(),
            ));
        }
    };

    // Capture the VERIFIED authenticated_data (AAD) before consuming the
    // ProcessedMessage. `ProcessedMessage::aad()` is post-verification: it is the
    // AAD covered by the committer's leaf signature (and, under PURE_CIPHERTEXT,
    // the AEAD tag), so decoding the convergent timestamp from it yields an
    // authenticated value, not one trusted on the wire (ADR-057).
    let aad = processed.aad().to_vec();

    // Resolve the sender DID from their leaf credential before consuming the
    // ProcessedMessage.
    let sender = processed.sender().clone();
    let Sender::Member(sender_leaf_index) = sender else {
        return Err(MlsError::DecryptionFailed(
            "sender is not a group member".to_string(),
        ));
    };
    let g = group.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
    let sender_credential = g
        .members()
        .find(|m| m.index == sender_leaf_index)
        .map(|m| m.credential)
        .ok_or_else(|| {
            MlsError::DecryptionFailed(format!(
                "sender leaf index {sender_leaf_index:?} not found in group members"
            ))
        })?;
    let sender_did = credential_to_did(&sender_credential)?;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            // ADR-011 exclusion taxonomy §2: an application message is NOT a
            // convergent Merkle leaf (`MessageSent` is per-author with no total
            // delivery order), so it binds no convergent timestamp — it is plain
            // encrypted and carries no AAD. Nothing is decoded here; the receiver
            // records it as local history.
            Ok(InboundChange::Application {
                plaintext: app_msg.into_bytes(),
                sender_did,
            })
        }
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            // Inspect the staged commit's proposals BEFORE merging. openmls lets
            // us read `add_proposals()` / `remove_proposals()` off the
            // StagedCommit while the group is still on its current epoch, so we
            // can decide whether to merge WITHOUT first mutating MLS state.

            // Recover the removed DIDs by mapping each Remove proposal's leaf
            // index to that member's credential in the CURRENT tree — the
            // removed leaf is still present pre-merge, and (critically) is read
            // here BEFORE any merge so this lookup is valid whether or not we go
            // on to merge.
            let mut removed_dids = Vec::new();
            {
                let g = group.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
                for remove in staged_commit.remove_proposals() {
                    let removed_index = remove.remove_proposal().removed();
                    let credential = g
                        .members()
                        .find(|m| m.index == removed_index)
                        .map(|m| m.credential)
                        .ok_or_else(|| {
                            MlsError::DecryptionFailed(format!(
                                "removed leaf index {removed_index:?} not found in group members"
                            ))
                        })?;
                    removed_dids.push(credential_to_did(&credential)?);
                }
            }

            // FAIL-CLOSED: a Remove-bearing Commit is unsupported by this seam.
            // Reject it WITHOUT merging — drop the StagedCommit here, leaving the
            // MLS group on its current epoch. MLS state and the caller's
            // SCP-layer state stay mutually consistent (pre-remove); the group
            // remains usable. Merging first and rejecting afterwards would
            // advance the MLS epoch + evict the leaf while the caller's
            // membership/log stayed put — an internal MLS-vs-SCP skew. We do not
            // merge before we have decided the Commit is one we can converge.
            if !removed_dids.is_empty() {
                // `staged_commit` is dropped at the end of this block without
                // ever being passed to `merge_staged_commit`, so the group is
                // unchanged. The Remove-refusal is decided FIRST (a Remove-bearing
                // Commit is rejected regardless of any AAD), matching the pre-merge
                // ordering: Remove-refusal → Lifetime brackets → AAD decode →
                // merge.
                return Ok(InboundChange::UnsupportedMembershipChange {
                    sender_did,
                    removed_dids,
                });
            }

            // Recover the added DIDs from the Add proposals' KeyPackage leaf
            // credentials. These KeyPackages were validated by process_message (a
            // Commit carrying an invalid Add is rejected above), so the DIDs are
            // cryptographically authenticated, not advisory.
            //
            // SECURITY (ADR-057 §Prereq-1): re-validate each Add proposal's
            // KeyPackage `Lifetime` against the injected hardened clock (plus the
            // RFC 9420 max-range bound) BEFORE merging. process_message ran
            // openmls's own `Lifetime::is_valid` on its un-injectable (wasm:
            // unhardened) clock; this bracket is the hardened counterpart. On
            // failure we return WITHOUT merging (via `?`), leaving the group on
            // its current epoch — fail-closed, consistent with the Remove path
            // above.
            //
            // ADR-057 sender-key distribution INVARIANT 3 (fail-closed): each Add
            // is recovered in the SAME pre-merge pass — its DID and its published
            // `scp_wrapping_key` leaf extension — so a bystander can HPKE-seal its
            // sender key to the new member (§9.16.1). An Add with no wrapping key is
            // rejected pre-merge (via `?`), leaving the group on its current epoch.
            let (added_dids, added_wrapping_keys) =
                recover_added_members_pre_merge(&staged_commit, clock)?;

            // ADR-057: only an add-Commit stamps convergent MemberJoined leaves,
            // so only an add-Commit binds a convergent timestamp. Decode it from
            // the verified AAD and adopt it VERBATIM (no receiver-side window, no
            // clock verdict — a per-receiver verdict would itself be a §9.9.3
            // violation) IFF this Commit adds members. A no-add Commit (e.g. a
            // self-update) carries no AAD and stamps no leaf → `None`. A missing /
            // malformed AAD on an add-Commit rejects it here via `?`, pre-merge,
            // so the group stays on its current epoch (fail-closed, consistent
            // with the Remove path and the Lifetime bracket above).
            let committer_timestamp_secs = if added_dids.is_empty() {
                None
            } else {
                Some(decode_convergent_timestamp_aad(&aad)?)
            };

            // Only now — having confirmed the change carries no Remove and every
            // Add is supported — merge the staged commit to advance the group
            // epoch (mirrors decrypt_with_sender_did — without this the group is
            // corrupted).
            let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
            g.merge_staged_commit(&group.provider, *staged_commit)
                .map_err(|e| {
                    MlsError::CommitProcessingFailed(format!("merging staged commit: {e}"))
                })?;

            Ok(InboundChange::Commit {
                sender_did,
                added_dids,
                added_wrapping_keys,
                committer_timestamp_secs,
            })
        }
        ProcessedMessageContent::ProposalMessage(_)
        | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
            // A bare proposal commits no membership change and stamps no leaf, so
            // it carries no convergent timestamp — the AAD is ignored here.
            Ok(InboundChange::Proposal { sender_did })
        }
    }
}

/// Serializes an [`MlsMessageOut`] to bytes for transmission.
///
/// This is a convenience function for converting the output of [`encrypt`]
/// into a byte vector suitable for transport. The receiver can pass these
/// bytes to [`decrypt`].
///
/// # Errors
///
/// Returns [`MlsError::EncryptionFailed`] if TLS serialization fails.
pub fn serialize_ciphertext(message: &MlsMessageOut) -> Result<Vec<u8>, MlsError> {
    message
        .tls_serialize_detached()
        .map_err(|e| MlsError::EncryptionFailed(format!("serializing ciphertext: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::ScpCredential;
    use crate::group::{
        add_member, add_member_with_convergent_timestamp, create_group, generate_key_package,
        generate_key_package_with_wrapping_key, join_group,
    };
    use scp_clock::{SystemClock, TestClock};

    #[allow(clippy::unwrap_used)]
    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_did::SigningKeyId::Active,
        )
        .unwrap()
    }

    /// Helper: set up Alice and Bob in a shared group.
    /// Returns (`alice_group`, `bob_group`).
    #[allow(clippy::unwrap_used)]
    fn setup_alice_bob() -> (ScpMlsGroup, ScpMlsGroup) {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred, &SystemClock).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();

        let add_result = add_member(&mut alice_group, bob_kp, &SystemClock).unwrap();

        // Bob joins using the Welcome message.
        let bob_group = join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

        (alice_group, bob_group)
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn encrypt_decrypt_roundtrip() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();

        let plaintext = b"Hello, Bob!";

        // Alice encrypts.
        let ciphertext_msg = encrypt(&mut alice_group, plaintext).unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        // Bob decrypts.
        let decrypted = decrypt(&mut bob_group, &ciphertext_bytes).unwrap();
        assert_eq!(
            decrypted, plaintext,
            "decrypted plaintext must match original"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn encrypt_decrypt_empty_plaintext() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();

        let plaintext = b"";

        let ciphertext_msg = encrypt(&mut alice_group, plaintext).unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        let decrypted = decrypt(&mut bob_group, &ciphertext_bytes).unwrap();
        assert_eq!(decrypted, plaintext, "empty plaintext roundtrip must work");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_invalid_membership_tag() {
        let (_alice_group, mut bob_group) = setup_alice_bob();

        // Create a completely separate group (Charlie, not a member of
        // Alice/Bob's group) and encrypt a message there. This produces
        // a ciphertext with a membership tag from wrong epoch secrets.
        let charlie_cred = test_credential("charlie");
        let mut charlie_group = create_group(&charlie_cred, &SystemClock).unwrap();

        // Add a dummy member so Charlie can encrypt (OpenMLS may require
        // at least 2 members, but single-member encrypt should work too).
        let ciphertext_msg = encrypt(&mut charlie_group, b"rogue message").unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        // Bob tries to decrypt Charlie's message — should fail because
        // the membership tag doesn't match Bob's group secrets.
        let result = decrypt(&mut bob_group, &ciphertext_bytes);
        assert!(
            result.is_err(),
            "decrypt must reject ciphertext with invalid membership tag"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_rejects_replayed_ciphertext() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();

        let plaintext = b"replay me";

        // Alice encrypts once.
        let ciphertext_msg = encrypt(&mut alice_group, plaintext).unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        // Bob decrypts successfully the first time.
        let decrypted = decrypt(&mut bob_group, &ciphertext_bytes).unwrap();
        assert_eq!(decrypted, plaintext);

        // Bob tries to decrypt the same ciphertext again — should fail
        // because the generation number has already been consumed.
        let replay_result = decrypt(&mut bob_group, &ciphertext_bytes);
        assert!(
            replay_result.is_err(),
            "decrypt must reject replayed ciphertext (same generation number)"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn encrypt_on_destroyed_group_fails() {
        let (mut alice_group, _bob_group) = setup_alice_bob();

        crate::group::destroy_group(&mut alice_group).unwrap();

        let result = encrypt(&mut alice_group, b"should fail");
        assert!(result.is_err(), "encrypt must fail on destroyed group");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_on_destroyed_group_fails() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();

        let ciphertext_msg = encrypt(&mut alice_group, b"hello").unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        crate::group::destroy_group(&mut bob_group).unwrap();

        let result = decrypt(&mut bob_group, &ciphertext_bytes);
        assert!(result.is_err(), "decrypt must fail on destroyed group");
    }

    #[test]
    fn decrypt_rejects_garbage_bytes() {
        let (_alice_group, mut bob_group) = setup_alice_bob();

        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = decrypt(&mut bob_group, &garbage);
        assert!(
            result.is_err(),
            "decrypt must reject malformed ciphertext bytes"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn multiple_messages_decrypt_in_order() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();

        let messages: Vec<&[u8]> = vec![b"first", b"second", b"third"];
        let mut ciphertext_bytes_list = Vec::new();

        for msg in &messages {
            let ct = encrypt(&mut alice_group, msg).unwrap();
            ciphertext_bytes_list.push(serialize_ciphertext(&ct).unwrap());
        }

        for (i, ct_bytes) in ciphertext_bytes_list.iter().enumerate() {
            let decrypted = decrypt(&mut bob_group, ct_bytes).unwrap();
            assert_eq!(
                decrypted, messages[i],
                "message {i} must roundtrip correctly"
            );
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_returns_error_for_tampered_aead_tag() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();

        let plaintext = b"tamper target";

        // Alice encrypts a legitimate message.
        let ciphertext_msg = encrypt(&mut alice_group, plaintext).unwrap();
        let mut ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        // Tamper with the last byte (corrupts the AEAD authentication tag).
        if let Some(byte) = ciphertext_bytes.last_mut() {
            *byte ^= 0xFF;
        }

        // Must return an error (not panic) thanks to the catch_unwind guard.
        let result = decrypt(&mut bob_group, &ciphertext_bytes);
        assert!(
            result.is_err(),
            "decrypt must return error for tampered AEAD tag, not panic"
        );

        // Verify the error is DecryptionFailed.
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("decryption failed"),
            "error should indicate decryption failure, got: {err_msg}"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn group_remains_usable_after_caught_decrypt_panic() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();

        // First: trigger a caught panic via tampered ciphertext.
        let ct_msg = encrypt(&mut alice_group, b"will be tampered").unwrap();
        let mut tampered_bytes = serialize_ciphertext(&ct_msg).unwrap();
        if let Some(byte) = tampered_bytes.last_mut() {
            *byte ^= 0xFF;
        }

        let bad_result = decrypt(&mut bob_group, &tampered_bytes);
        assert!(bad_result.is_err(), "tampered ciphertext must fail");

        // Second: encrypt and decrypt a legitimate message to prove the
        // group is still functional after the caught panic.
        let good_plaintext = b"still works";
        let good_ct_msg = encrypt(&mut alice_group, good_plaintext).unwrap();
        let good_ct_bytes = serialize_ciphertext(&good_ct_msg).unwrap();

        let decrypted = decrypt(&mut bob_group, &good_ct_bytes).unwrap();
        assert_eq!(
            decrypted, good_plaintext,
            "group must remain usable after a caught decrypt panic"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_with_sender_did_returns_application_variant() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();

        let plaintext = b"hello from alice";
        let ct_msg = encrypt(&mut alice_group, plaintext).unwrap();
        let ct_bytes = serialize_ciphertext(&ct_msg).unwrap();

        let content = decrypt_with_sender_did(&mut bob_group, &ct_bytes, &SystemClock).unwrap();
        assert!(
            matches!(&content, DecryptedContent::Application { .. }),
            "expected Application variant"
        );
        if let DecryptedContent::Application {
            plaintext: pt,
            sender_did,
        } = content
        {
            assert_eq!(pt, plaintext, "plaintext must roundtrip");
            assert!(
                sender_did.starts_with("did:dht:z6Mk"),
                "sender_did must be a DID, got: {sender_did}"
            );
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_with_sender_did_handles_commit_without_corruption() {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred, &SystemClock).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();

        let add_result = add_member(&mut alice_group, bob_kp, &SystemClock).unwrap();
        let mut bob_group = join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

        // Record Bob's epoch before Alice's update.
        let bob_epoch_before = bob_group.group.as_ref().unwrap().epoch().as_u64();

        // Alice proposes an update and commits it, producing a Commit message.
        let alice_g = alice_group.group.as_mut().unwrap();
        let alice_signer = alice_group.signer.as_ref().unwrap();
        let bundle = alice_g
            .self_update(
                &alice_group.provider,
                alice_signer,
                LeafNodeParameters::default(),
            )
            .unwrap();
        let commit_msg = bundle.into_commit();
        // Re-borrow after consuming bundle to avoid aliasing.
        let alice_g = alice_group.group.as_mut().unwrap();
        alice_g.merge_pending_commit(&alice_group.provider).unwrap();

        // Serialize the Commit message for Bob.
        let commit_bytes = commit_msg.tls_serialize_detached().unwrap();

        // Bob processes the Commit through decrypt_with_sender_did.
        let content = decrypt_with_sender_did(&mut bob_group, &commit_bytes, &SystemClock).unwrap();
        assert!(
            matches!(&content, DecryptedContent::Commit { .. }),
            "expected Commit variant"
        );
        if let DecryptedContent::Commit { sender_did } = &content {
            assert!(
                sender_did.starts_with("did:dht:z6Mk"),
                "sender_did must be a DID, got: {sender_did}"
            );
        }

        // Verify the epoch advanced — proves merge_staged_commit was called.
        let bob_epoch_after = bob_group.group.as_ref().unwrap().epoch().as_u64();
        assert_eq!(
            bob_epoch_after,
            bob_epoch_before + 1,
            "Bob's epoch must advance after processing a Commit"
        );

        // Verify the group is still functional after processing the Commit.
        let plaintext = b"post-commit message";
        let ct_msg = encrypt(&mut alice_group, plaintext).unwrap();
        let ct_bytes = serialize_ciphertext(&ct_msg).unwrap();
        let content = decrypt_with_sender_did(&mut bob_group, &ct_bytes, &SystemClock).unwrap();
        assert!(
            matches!(&content, DecryptedContent::Application { .. }),
            "expected Application variant after Commit"
        );
        if let DecryptedContent::Application { plaintext: pt, .. } = content {
            assert_eq!(pt, plaintext, "must decrypt after Commit processing");
        }
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn decrypt_with_membership_changes_surfaces_added_did() {
        // Alice creates, adds Bob, then adds Carol. The existing member Bob
        // processes Alice's add-Carol Commit and the seam must surface Carol's
        // DID (recovered from the Add proposal's KeyPackage), so an existing
        // member can mirror the committer's MemberJoined leaf and converge.
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred, &SystemClock).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
        let add_bob = add_member(&mut alice_group, bob_kp, &SystemClock).unwrap();
        let mut bob_group = join_group(&add_bob.welcome, bob_provider, bob_signer).unwrap();

        let carol_cred = test_credential("carol");
        // ADR-057 sender-key distribution: Carol's KeyPackage must publish an
        // scp_wrapping_key leaf extension, or the fail-closed add-extraction in
        // decrypt_with_membership_changes rejects the add pre-merge (INVARIANT 3).
        let carol_wk = [0xCC_u8; 32];
        let (carol_kp_bundle, _carol_signer, _carol_provider) =
            generate_key_package_with_wrapping_key(&carol_cred, Some(&carol_wk), &SystemClock)
                .unwrap();
        let carol_kp: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
        // ADR-057: the add-Carol commit binds a convergent timestamp into
        // its AAD; Bob recovers + validates it on receive.
        let ts = SystemClock.now_secs();
        let add_carol =
            add_member_with_convergent_timestamp(&mut alice_group, carol_kp, &SystemClock, ts)
                .unwrap();

        let commit_bytes = add_carol.commit.tls_serialize_detached().unwrap();
        let change =
            decrypt_with_membership_changes(&mut bob_group, &commit_bytes, &SystemClock).unwrap();

        match change {
            InboundChange::Commit {
                sender_did,
                added_dids,
                added_wrapping_keys,
                committer_timestamp_secs,
            } => {
                assert_eq!(sender_did, "did:dht:z6Mkalice", "committer is Alice");
                assert_eq!(
                    added_dids,
                    vec!["did:dht:z6Mkcarol".to_owned()],
                    "the seam surfaces Carol's DID from the Add proposal"
                );
                assert_eq!(
                    added_wrapping_keys,
                    vec![carol_wk],
                    "the seam surfaces Carol's scp_wrapping_key from the Add proposal's leaf, \
                     1:1 with added_dids (ADR-057 sender-key distribution)"
                );
                assert_eq!(
                    committer_timestamp_secs,
                    Some(ts),
                    "the authenticated convergent timestamp is recovered from the AAD and adopted verbatim"
                );
            }
            other => panic!("expected Commit change, got {other:?}"),
        }

        // The merge advanced Bob's epoch (proves the commit was applied).
        assert_eq!(bob_group.epoch().unwrap(), 2, "two adds → epoch 2");
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
    fn decrypt_with_membership_changes_rejects_add_without_wrapping_key() {
        // ADR-057 sender-key distribution INVARIANT 3: an add whose KeyPackage
        // leaf carries NO scp_wrapping_key extension must be rejected pre-merge —
        // admitting a member no peer can HPKE-seal a sender key to would silently
        // break §9.16 distribution. The rejection is fail-closed: the group is
        // left on its current epoch (no half-merge).
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred, &SystemClock).unwrap();

        let bob_cred = test_credential("bob");
        let bob_wk = [0xBB_u8; 32];
        let (bob_kp_bundle, bob_signer, bob_provider) =
            generate_key_package_with_wrapping_key(&bob_cred, Some(&bob_wk), &SystemClock).unwrap();
        let add_bob = add_member(
            &mut alice_group,
            bob_kp_bundle.key_package().clone().into(),
            &SystemClock,
        )
        .unwrap();
        let mut bob_group = join_group(&add_bob.welcome, bob_provider, bob_signer).unwrap();

        // Carol's KeyPackage has NO wrapping key (plain generate_key_package).
        let carol_cred = test_credential("carol");
        let (carol_kp_bundle, _carol_signer, _carol_provider) =
            generate_key_package(&carol_cred, &SystemClock).unwrap();
        let add_carol = add_member_with_convergent_timestamp(
            &mut alice_group,
            carol_kp_bundle.key_package().clone().into(),
            &SystemClock,
            SystemClock.now_secs(),
        )
        .unwrap();
        let add_carol_bytes = add_carol.commit.tls_serialize_detached().unwrap();

        let bob_epoch_before = bob_group.epoch().unwrap();
        let err = decrypt_with_membership_changes(&mut bob_group, &add_carol_bytes, &SystemClock)
            .expect_err("an add with no scp_wrapping_key must be rejected pre-merge");
        assert!(
            matches!(err, MlsError::ExtensionError(_)),
            "expected a fail-closed ExtensionError, got: {err:?}"
        );
        // FAIL-CLOSED: the rejected add did NOT advance Bob's epoch (no half-merge).
        assert_eq!(
            bob_group.epoch().unwrap(),
            bob_epoch_before,
            "a rejected add-Commit must NOT advance the MLS epoch"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn decrypt_with_membership_changes_rejects_remove_without_merging() {
        // Alice creates, adds Bob and Carol, then removes Carol. The existing
        // member Bob processes the remove Commit; the seam must REJECT it as
        // UnsupportedMembershipChange (surfacing Carol's DID from the pre-merge
        // tree) WITHOUT merging — so Bob's MLS group stays on its current epoch
        // and is left consistent (fail-closed, not half-applied).
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred, &SystemClock).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        let add_bob = add_member(
            &mut alice_group,
            bob_kp_bundle.key_package().clone().into(),
            &SystemClock,
        )
        .unwrap();
        let mut bob_group = join_group(&add_bob.welcome, bob_provider, bob_signer).unwrap();

        let carol_cred = test_credential("carol");
        // ADR-057 sender-key distribution INVARIANT 3: Carol's KeyPackage must
        // publish an scp_wrapping_key leaf extension so Bob's add-Carol receive
        // (a Commit-arm decrypt) accepts pre-merge.
        let (carol_kp_bundle, _carol_signer, _carol_provider) =
            generate_key_package_with_wrapping_key(&carol_cred, Some(&[0xCC_u8; 32]), &SystemClock)
                .unwrap();
        // ADR-057: bind a convergent timestamp so Bob's add-Carol receive
        // (a Commit-arm decrypt) accepts.
        let add_carol = add_member_with_convergent_timestamp(
            &mut alice_group,
            carol_kp_bundle.key_package().clone().into(),
            &SystemClock,
            SystemClock.now_secs(),
        )
        .unwrap();
        let add_carol_bytes = add_carol.commit.tls_serialize_detached().unwrap();
        // Bob processes the add-Carol commit so his tree contains Carol.
        decrypt_with_membership_changes(&mut bob_group, &add_carol_bytes, &SystemClock).unwrap();

        // Alice removes Carol.
        let alice_own = alice_group.own_leaf_index().unwrap();
        let members = alice_group.members().unwrap();
        let carol_member = members
            .iter()
            .find(|m| {
                m.index != alice_own && {
                    let bc = BasicCredential::try_from(m.credential.clone()).unwrap();
                    let sc = crate::credential::ScpCredential::from_bytes(bc.identity()).unwrap();
                    sc.did == "did:dht:z6Mkcarol"
                }
            })
            .unwrap();
        let remove = crate::group::remove_member(&mut alice_group, carol_member.index).unwrap();
        let remove_bytes = remove.commit.tls_serialize_detached().unwrap();

        // Bob is on epoch 2 (create + add-Bob + add-Carol = two epoch advances
        // since his epoch-0 join: join epoch 1, add-Carol epoch 2). Capture it
        // so we can prove the rejected remove did NOT advance it.
        let bob_epoch_before = bob_group.epoch().unwrap();

        let change =
            decrypt_with_membership_changes(&mut bob_group, &remove_bytes, &SystemClock).unwrap();
        match change {
            InboundChange::UnsupportedMembershipChange {
                sender_did,
                removed_dids,
            } => {
                assert_eq!(sender_did, "did:dht:z6Mkalice", "committer is Alice");
                assert_eq!(
                    removed_dids,
                    vec!["did:dht:z6Mkcarol".to_owned()],
                    "the seam surfaces Carol's DID from the pre-merge tree"
                );
            }
            other => panic!("expected UnsupportedMembershipChange, got {other:?}"),
        }

        // FAIL-CLOSED, NOT half-applied: the remove Commit was dropped without
        // merging, so Bob's MLS group is still on the SAME epoch it was before.
        assert_eq!(
            bob_group.epoch().unwrap(),
            bob_epoch_before,
            "a rejected remove-Commit must NOT advance the MLS epoch (no half-merge)"
        );

        // The group is still usable on the old epoch: Bob can still decrypt an
        // application message Alice (still on the pre-remove epoch herself, since
        // she committed the remove but Bob never applied it) — prove via a fresh
        // Bob-side encrypt/serialize roundtrip that his group is intact.
        let still_works = encrypt(&mut bob_group, b"post-reject").unwrap();
        let _ = serialize_ciphertext(&still_works).unwrap();
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn decrypt_with_membership_changes_application_variant() {
        // An application message is plain-encrypted (no AAD): ADR-011 excludes
        // `MessageSent` from the convergent Merkle log, so the seam surfaces only
        // the plaintext + sender DID, with no convergent timestamp.
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let ct = encrypt(&mut alice_group, b"hi").unwrap();
        let ct_bytes = serialize_ciphertext(&ct).unwrap();
        let change =
            decrypt_with_membership_changes(&mut bob_group, &ct_bytes, &SystemClock).unwrap();
        match change {
            InboundChange::Application {
                plaintext,
                sender_did,
            } => {
                assert_eq!(plaintext, b"hi");
                assert!(sender_did.starts_with("did:dht:z6Mk"));
            }
            other => panic!("expected Application change, got {other:?}"),
        }
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn decrypt_with_membership_changes_no_add_self_update_commit_carries_no_timestamp() {
        // A no-add Commit (a self-update) stamps no MemberJoined leaf, so it binds
        // no convergent timestamp and carries no AAD. The seam must NOT try to
        // decode a timestamp (the pre-fix code decoded unconditionally and failed
        // a self-update closed as ConvergentTimestampMissing — BLACK-T3-03): it
        // returns `added_dids` empty, `committer_timestamp_secs` None, and MERGES
        // (the epoch advances).
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let bob_epoch_before = bob_group.epoch().unwrap();

        // Alice self-updates (a Commit with no Add and no Remove proposals).
        let alice_g = alice_group.group.as_mut().unwrap();
        let alice_signer = alice_group.signer.as_ref().unwrap();
        let bundle = alice_g
            .self_update(
                &alice_group.provider,
                alice_signer,
                LeafNodeParameters::default(),
            )
            .unwrap();
        let commit_msg = bundle.into_commit();
        let alice_g = alice_group.group.as_mut().unwrap();
        alice_g.merge_pending_commit(&alice_group.provider).unwrap();
        let commit_bytes = commit_msg.tls_serialize_detached().unwrap();

        let change =
            decrypt_with_membership_changes(&mut bob_group, &commit_bytes, &SystemClock).unwrap();
        match change {
            InboundChange::Commit {
                added_dids,
                committer_timestamp_secs,
                ..
            } => {
                assert!(added_dids.is_empty(), "a self-update adds nobody");
                assert_eq!(
                    committer_timestamp_secs, None,
                    "a no-add Commit stamps no leaf, so it carries no timestamp"
                );
            }
            other => panic!("expected a no-add Commit change, got {other:?}"),
        }
        assert_eq!(
            bob_group.epoch().unwrap(),
            bob_epoch_before + 1,
            "a no-add Commit still advances the epoch (merged, not rejected)"
        );
    }

    #[test]
    fn inbound_change_debug_redacts_application_plaintext() {
        // ADR-057: a `{:?}`-formatted InboundChange::Application must print the
        // byte length, NEVER the decrypted cleartext (the tab is the plaintext
        // boundary).
        let secret = b"DO-NOT-LOG-THIS-DECRYPTED-PAYLOAD";
        let change = InboundChange::Application {
            plaintext: secret.to_vec(),
            sender_did: "did:dht:z6Mkalice".to_owned(),
        };
        let rendered = format!("{change:?}");
        assert!(
            !rendered.contains("DO-NOT-LOG-THIS-DECRYPTED-PAYLOAD"),
            "Debug must NOT leak the decrypted plaintext, got: {rendered}"
        );
        assert!(
            rendered.contains("<redacted") && rendered.contains(&format!("{} bytes", secret.len())),
            "Debug must report a redacted byte length, got: {rendered}"
        );
    }

    // -----------------------------------------------------------------------
    // ADR-057 §Prereq-1: staged-commit Add-proposal Lifetime bracketing
    // -----------------------------------------------------------------------
    //
    // A Commit whose Add proposal carries a KeyPackage with an expired Lifetime
    // (relative to the injected hardened clock) must be refused BEFORE merging —
    // the receiver's MLS epoch stays put (fail-closed), even though openmls's own
    // internal validation (real clock) accepted the Add during process_message.

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_with_sender_did_rejects_expired_add_commit_without_merging() {
        let real_now = SystemClock.now_secs();
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let bob_epoch_before = bob_group.epoch().unwrap();

        // Carol's KP is minted at real-now (not_after ~ real-now + 84d).
        let carol_cred = test_credential("carol");
        let (carol_kp_bundle, _s, _p) = generate_key_package(&carol_cred, &SystemClock).unwrap();
        let carol_kp: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
        let add_carol = add_member(&mut alice_group, carol_kp, &SystemClock).unwrap();
        let commit_bytes = add_carol.commit.tls_serialize_detached().unwrap();

        // Bob processes with a clock 100 days ahead: Carol's KP is expired
        // relative to the injected clock, so the add-commit is refused pre-merge.
        let hundred_days = 100 * 24 * 60 * 60;
        let future = scp_clock::TestClock::new(real_now + hundred_days);
        let err = decrypt_with_sender_did(&mut bob_group, &commit_bytes, &future).unwrap_err();
        assert!(
            matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }),
            "expected KeyPackageLifetimeInvalid, got {err:?}"
        );
        assert_eq!(
            bob_group.epoch().unwrap(),
            bob_epoch_before,
            "a refused add-commit must NOT advance the receiver's epoch (no half-merge)"
        );

        // The group stays usable on the old epoch.
        let ct = encrypt(&mut bob_group, b"still works").unwrap();
        let _ = serialize_ciphertext(&ct).unwrap();
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn decrypt_with_membership_changes_rejects_expired_add_commit_without_merging() {
        let real_now = SystemClock.now_secs();
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let bob_epoch_before = bob_group.epoch().unwrap();

        let carol_cred = test_credential("carol");
        let (carol_kp_bundle, _s, _p) = generate_key_package(&carol_cred, &SystemClock).unwrap();
        let carol_kp: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
        // Alice adds Carol with the REAL clock (so her side accepts Carol's KP,
        // whose not_after ~ real_now + 84d) but binds a convergent timestamp at
        // `real_now + 90d`. Bob then receives with a clock at that same +90d
        // value. The convergent timestamp in the AAD is adopted verbatim — there
        // is no receiver-side clock verdict on it — so the only clock-sensitive
        // check on this path is the MLS KeyPackage `Lifetime` bracket, which
        // surfaces the *Lifetime* failure: Carol's KP is expired at +90d. This
        // isolates the pre-merge Lifetime bracket; it is not a timestamp failure.
        let ninety_days = 90 * 24 * 60 * 60;
        let future_ts = real_now + ninety_days;
        let add_carol = add_member_with_convergent_timestamp(
            &mut alice_group,
            carol_kp,
            &SystemClock,
            future_ts,
        )
        .unwrap();
        let commit_bytes = add_carol.commit.tls_serialize_detached().unwrap();

        let future = TestClock::new(future_ts);
        let err =
            decrypt_with_membership_changes(&mut bob_group, &commit_bytes, &future).unwrap_err();
        assert!(
            matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }),
            "expected KeyPackageLifetimeInvalid, got {err:?}"
        );
        assert_eq!(
            bob_group.epoch().unwrap(),
            bob_epoch_before,
            "a refused add-commit must NOT advance the receiver's epoch (no half-merge)"
        );

        let ct = encrypt(&mut bob_group, b"still works").unwrap();
        let _ = serialize_ciphertext(&ct).unwrap();
    }

    // -----------------------------------------------------------------------
    // ADR-057: convergent-timestamp AAD authentication
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn membership_changes_application_carries_no_aad() {
        // A plain `encrypt` application message decrypts cleanly through the
        // membership-changes seam: ADR-011 excludes `MessageSent` from the
        // convergent log, so no AAD is expected and none is decoded — the receiver
        // records local history, not a leaf.
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let ct = encrypt(&mut alice_group, b"no aad here").unwrap();
        let bytes = serialize_ciphertext(&ct).unwrap();
        let change = decrypt_with_membership_changes(&mut bob_group, &bytes, &SystemClock).unwrap();
        assert!(
            matches!(change, InboundChange::Application { .. }),
            "a plain application message decodes without any AAD requirement, got {change:?}"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn membership_changes_missing_aad_commit_rejected_pre_merge() {
        // A plain `add_member` Commit (no AAD) processed by an existing member is
        // rejected pre-merge on the missing timestamp: the epoch is unchanged and
        // the group stays usable (fail-closed, not half-applied).
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let bob_epoch_before = bob_group.epoch().unwrap();

        let carol_cred = test_credential("carol");
        // Carol carries a wrapping key (an otherwise-valid add), so the Commit
        // reaches the convergent-timestamp AAD check rather than the fail-closed
        // wrapping-key check that precedes it (both are pre-merge).
        let (carol_kp_bundle, _s, _p) =
            generate_key_package_with_wrapping_key(&carol_cred, Some(&[0xCC_u8; 32]), &SystemClock)
                .unwrap();
        let carol_kp: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
        // Plain add_member — binds NO convergent-timestamp AAD.
        let add_carol = add_member(&mut alice_group, carol_kp, &SystemClock).unwrap();
        let commit_bytes = add_carol.commit.tls_serialize_detached().unwrap();

        let err = decrypt_with_membership_changes(&mut bob_group, &commit_bytes, &SystemClock)
            .unwrap_err();
        assert!(
            matches!(err, MlsError::ConvergentTimestampMissing),
            "an add-Commit with no convergent-timestamp AAD must be rejected as missing, got {err:?}"
        );
        assert_eq!(
            bob_group.epoch().unwrap(),
            bob_epoch_before,
            "a rejected (missing-AAD) add-Commit must NOT advance the epoch (no half-merge)"
        );
        // The group stays usable on the unchanged epoch.
        let ct = encrypt(&mut bob_group, b"still works").unwrap();
        let _ = serialize_ciphertext(&ct).unwrap();
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn forged_add_commit_aad_is_decryption_failed() {
        // An add-Commit's convergent timestamp lives in the AUTHENTICATED AAD,
        // covered by the committer's leaf signature and the PrivateMessage AEAD
        // tag. Flipping a wire byte breaks the tag, so the frame is rejected as
        // DecryptionFailed pre-merge — a relay cannot alter the Commit (or its
        // timestamp) and have it accepted.
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let bob_epoch_before = bob_group.epoch().unwrap();

        let carol_cred = test_credential("carol");
        let (carol_kp_bundle, _s, _p) = generate_key_package(&carol_cred, &SystemClock).unwrap();
        let carol_kp: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
        let ts = SystemClock.now_secs();
        let add_carol =
            add_member_with_convergent_timestamp(&mut alice_group, carol_kp, &SystemClock, ts)
                .unwrap();
        let mut bytes = add_carol.commit.tls_serialize_detached().unwrap();
        if let Some(byte) = bytes.last_mut() {
            *byte ^= 0xFF;
        }
        let err =
            decrypt_with_membership_changes(&mut bob_group, &bytes, &SystemClock).unwrap_err();
        assert!(
            matches!(err, MlsError::DecryptionFailed(_)),
            "a forged add-Commit AAD must fail the AEAD tag (DecryptionFailed), got {err:?}"
        );
        assert_eq!(
            bob_group.epoch().unwrap(),
            bob_epoch_before,
            "a rejected (forged) add-Commit must NOT advance the epoch"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
    fn forged_add_commit_aad_region_flip_is_decryption_failed() {
        // Strictly stronger than the tag-region flip above: this mutates a byte
        // INSIDE the transmitted convergent-timestamp AAD blob itself, not the
        // trailing AEAD tag. The AAD rides in `PrivateMessage.authenticated_data`,
        // which RFC 9420 §6.3.2 folds into the AEAD's associated data — so
        // altering the timestamp bytes on the wire breaks the tag and the frame
        // is rejected as DecryptionFailed at `process_message`, BEFORE the value
        // is ever decoded. This pins that the timestamp *field* is bound, not
        // merely that the frame carries an intact tag.
        use crate::convergent_timestamp::encode_convergent_timestamp_aad;

        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let bob_epoch_before = bob_group.epoch().unwrap();

        let carol_cred = test_credential("carol");
        let (carol_kp_bundle, _s, _p) = generate_key_package(&carol_cred, &SystemClock).unwrap();
        let carol_kp: KeyPackageIn = carol_kp_bundle.key_package().clone().into();
        // A distinctive timestamp so its encoded AAD blob is unambiguously
        // locatable in the cleartext `authenticated_data` on the wire.
        let ts: u64 = 0x0102_0304_0506_0708;
        let add_carol =
            add_member_with_convergent_timestamp(&mut alice_group, carol_kp, &SystemClock, ts)
                .unwrap();
        let mut bytes = add_carol.commit.tls_serialize_detached().unwrap();

        // Locate the 13-byte AAD blob (`SCPT` || version || u64-BE ts) and flip a
        // byte inside its timestamp field — proof the transmitted AAD is present
        // in the clear AND bound by the tag.
        let aad_blob = encode_convergent_timestamp_aad(ts);
        let aad_offset = bytes
            .windows(aad_blob.len())
            .position(|w| w == aad_blob)
            .expect("the convergent-timestamp AAD blob must ride in the clear on the wire");
        // Offset +5 is the first timestamp byte: magic[0..4] || version[4] || ts[5..13].
        bytes[aad_offset + 5] ^= 0xFF;

        let err =
            decrypt_with_membership_changes(&mut bob_group, &bytes, &SystemClock).unwrap_err();
        assert!(
            matches!(err, MlsError::DecryptionFailed(_)),
            "flipping a byte inside the authenticated timestamp AAD must fail the AEAD \
             tag (DecryptionFailed), proving the timestamp field is bound, got {err:?}"
        );
        assert_eq!(
            bob_group.epoch().unwrap(),
            bob_epoch_before,
            "a rejected (AAD-tampered) add-Commit must NOT advance the epoch"
        );
    }

    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(20))]
            #[test]
            #[allow(clippy::unwrap_used)]
            fn encrypt_decrypt_roundtrip_arbitrary(plaintext in proptest::collection::vec(any::<u8>(), 0..1024)) {
                let (mut alice_group, mut bob_group) = setup_alice_bob();

                let ciphertext_msg = encrypt(&mut alice_group, &plaintext).unwrap();
                let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

                let decrypted = decrypt(&mut bob_group, &ciphertext_bytes).unwrap();
                prop_assert_eq!(decrypted, plaintext);
            }
        }
    }
}
