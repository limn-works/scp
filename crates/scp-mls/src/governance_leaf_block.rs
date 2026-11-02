//! The governance leaf block every SCP Commit carries in its
//! `FramedContent.authenticated_data` (`07-trust-validation-and-capabilities.md`
//! §7.3.1.1 "Wire placement", ADR-066).
//!
//! The block has one fixed size, 32,805 bytes, so a relay cannot tell from a
//! Commit's length whether it executes a governance action:
//!
//! ```text
//! magic (b"SCPG") ‖ version (1) ‖ nonce (12) ‖ BE32(ciphertext_len = 32,784) ‖ ciphertext
//! ```
//!
//! `ciphertext` is AES-128-GCM over a 32,768-byte padded plaintext,
//! `BE32(body_len) ‖ body ‖ zero padding`, under
//! `MLS-Exporter("SCP-GOVERNANCE-LEAF-V1", UTF-8 context_id, 16)` from the
//! epoch the Commit is sent in. The additional data binds the block to its
//! group, epoch, and committer leaf.
//!
//! This module treats the body as opaque bytes; its record codec is SCP-331.
//! It holds:
//!
//! - the layout constants and the pure codec, [`encode_block`] and
//!   [`decode_block`], with every header-level canonical-encoding check;
//! - the exporter key, taken only through `MlsGroup::export_secret` (the
//!   sending epoch), never the staged commit's `export_secret` (the new epoch);
//! - [`seal_block`] and [`open_block`], which bind a block to a live group;
//! - the two-phase receive, [`receive_commit`] then
//!   [`StagedGovernanceCommit::merge`] or [`StagedGovernanceCommit::discard`],
//!   which returns the decrypted body, the sending epoch, and the pre-Commit
//!   tree before anything is merged.
//!
//! The committer entry points in [`crate::group`] and [`crate::ratchet`] set the
//! block on every Commit they build and pad the Commit to
//! [`COMMIT_PADDING_MULTIPLE`] (`09-security-model.md` §9.10.3 "Commits").

use openmls::group::{ExportedSecret, GroupExport};
use openmls::prelude::ContentType;
use openmls::prelude::{
    LeafNodeIndex, Member, MlsGroup, ProcessedMessageContent, ProtocolMessage, StagedCommit,
};
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::AeadType;
use zeroize::Zeroizing;

use crate::InMemoryMlsProvider;
use crate::admission::{AdmittedLeaf, LifetimeCheck, MemberLeaves, admit_staged_commit};
use crate::error::{GovernanceLeafBlockError, MlsError};
use crate::group::ScpMlsGroup;

/// The block's magic, `b"SCPG"`.
pub const GOVERNANCE_LEAF_BLOCK_MAGIC: [u8; 4] = *b"SCPG";
/// The block format version this crate writes and accepts.
pub const GOVERNANCE_LEAF_BLOCK_VERSION: u8 = 1;
/// The length of the random AES-128-GCM nonce.
pub const GOVERNANCE_LEAF_NONCE_LEN: usize = 12;
/// The header before the ciphertext: magic, version, nonce, `ciphertext_len`.
pub const GOVERNANCE_LEAF_HEADER_LEN: usize = 4 + 1 + GOVERNANCE_LEAF_NONCE_LEN + 4;
/// The padded plaintext length.
pub const GOVERNANCE_LEAF_PLAINTEXT_LEN: usize = 32_768;
/// The AES-128-GCM tag length.
pub const GOVERNANCE_LEAF_TAG_LEN: usize = 16;
/// The one `ciphertext_len` a block carries: the padded plaintext plus the tag.
pub const GOVERNANCE_LEAF_CIPHERTEXT_LEN: usize =
    GOVERNANCE_LEAF_PLAINTEXT_LEN + GOVERNANCE_LEAF_TAG_LEN;
/// The whole block, which is the whole of a Commit's `authenticated_data`.
pub const GOVERNANCE_LEAF_BLOCK_LEN: usize =
    GOVERNANCE_LEAF_HEADER_LEN + GOVERNANCE_LEAF_CIPHERTEXT_LEN;
/// The largest body one block carries: the padded plaintext less `body_len`.
pub const MAX_GOVERNANCE_LEAF_BODY_LEN: usize = GOVERNANCE_LEAF_PLAINTEXT_LEN - 4;
/// The MLS exporter label of the block key (§7.3.1.1 "Encryption").
pub const GOVERNANCE_LEAF_EXPORTER_LABEL: &str = "SCP-GOVERNANCE-LEAF-V1";
/// The block key length, AES-128.
pub const GOVERNANCE_LEAF_KEY_LEN: usize = 16;
/// Every Commit's `PrivateMessage` `ciphertext` is a multiple of this
/// (`09-security-model.md` §9.10.3 "Commits", §9.18.A; ADR-066 decision 32).
pub const COMMIT_PADDING_MULTIPLE: usize = 4_096;

const _: () = assert!(GOVERNANCE_LEAF_HEADER_LEN == 21);
const _: () = assert!(GOVERNANCE_LEAF_CIPHERTEXT_LEN == 32_784);
const _: () = assert!(GOVERNANCE_LEAF_BLOCK_LEN == 32_805);
const _: () = assert!(MAX_GOVERNANCE_LEAF_BODY_LEN == 32_764);

/// `ciphertext_len` as it is written, big-endian.
const CIPHERTEXT_LEN_FIELD: u32 = 32_784;
const _: () = assert!(CIPHERTEXT_LEN_FIELD as usize == GOVERNANCE_LEAF_CIPHERTEXT_LEN);

/// What the block's additional data binds it to (§7.3.1.1 "Encryption"): the
/// MLS group, the sending epoch, and the committer's leaf index in the sending
/// epoch's tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockBinding<'a> {
    /// The MLS group ID.
    pub group_id: &'a [u8],
    /// The epoch the Commit is sent in.
    pub epoch: u64,
    /// The committer's leaf index in the sending epoch's tree.
    pub sender_leaf_index: u32,
}

/// The block a committer entry point puts on its Commit.
///
/// It names the context whose key encrypts it, and the body. An empty `body`
/// is the empty block (`body_len` 0), which every Commit that carries no
/// governance body sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernanceLeafBlockInput<'a> {
    /// The text form of the context's id; its UTF-8 bytes are the exporter
    /// context. Must not be empty.
    pub context_id: &'a str,
    /// The body bytes, at most [`MAX_GOVERNANCE_LEAF_BODY_LEN`]. The record
    /// codec that produces them is SCP-331's.
    pub body: &'a [u8],
}

impl<'a> GovernanceLeafBlockInput<'a> {
    /// The empty block (`body_len` 0) for `context_id`, which a Commit that
    /// carries no governance body sends.
    #[must_use]
    pub const fn empty(context_id: &'a str) -> Self {
        Self {
            context_id,
            body: &[],
        }
    }
}

/// The AEAD additional data:
/// `magic ‖ version ‖ BE32(len(group_id)) ‖ group_id ‖ BE64(epoch) ‖ BE32(sender_leaf_index)`.
fn additional_data(binding: &BlockBinding<'_>) -> Result<Vec<u8>, GovernanceLeafBlockError> {
    let group_id_len = u32::try_from(binding.group_id.len()).map_err(|_| {
        GovernanceLeafBlockError::GroupIdTooLong {
            len: binding.group_id.len(),
        }
    })?;
    let mut aad = Vec::with_capacity(4 + 1 + 4 + binding.group_id.len() + 8 + 4);
    aad.extend_from_slice(&GOVERNANCE_LEAF_BLOCK_MAGIC);
    aad.push(GOVERNANCE_LEAF_BLOCK_VERSION);
    aad.extend_from_slice(&group_id_len.to_be_bytes());
    aad.extend_from_slice(binding.group_id);
    aad.extend_from_slice(&binding.epoch.to_be_bytes());
    aad.extend_from_slice(&binding.sender_leaf_index.to_be_bytes());
    Ok(aad)
}

/// Encodes and encrypts one block with an explicit key and nonce.
///
/// The padded plaintext is `BE32(body_len) ‖ body ‖ zeros` to 32,768 bytes; an
/// empty `body` gives the empty block.
///
/// # Errors
///
/// [`GovernanceLeafBlockError::BodyTooLarge`] for a body above
/// [`MAX_GOVERNANCE_LEAF_BODY_LEN`], [`GovernanceLeafBlockError::GroupIdTooLong`],
/// or [`GovernanceLeafBlockError::Seal`] when the AEAD fails or returns a
/// ciphertext of another length.
pub fn encode_block(
    crypto: &impl OpenMlsCrypto,
    key: &[u8; GOVERNANCE_LEAF_KEY_LEN],
    nonce: &[u8; GOVERNANCE_LEAF_NONCE_LEN],
    binding: &BlockBinding<'_>,
    body: &[u8],
) -> Result<Vec<u8>, GovernanceLeafBlockError> {
    if body.len() > MAX_GOVERNANCE_LEAF_BODY_LEN {
        return Err(GovernanceLeafBlockError::BodyTooLarge { len: body.len() });
    }
    let body_len = u32::try_from(body.len())
        .map_err(|_| GovernanceLeafBlockError::BodyTooLarge { len: body.len() })?;
    let mut plaintext = Zeroizing::new(vec![0u8; GOVERNANCE_LEAF_PLAINTEXT_LEN]);
    plaintext[..4].copy_from_slice(&body_len.to_be_bytes());
    plaintext[4..4 + body.len()].copy_from_slice(body);

    let aad = additional_data(binding)?;
    let ciphertext = crypto
        .aead_encrypt(AeadType::Aes128Gcm, key, &plaintext, nonce, &aad)
        .map_err(|e| GovernanceLeafBlockError::Seal(format!("AES-128-GCM: {e:?}")))?;
    if ciphertext.len() != GOVERNANCE_LEAF_CIPHERTEXT_LEN {
        return Err(GovernanceLeafBlockError::Seal(format!(
            "AES-128-GCM returned {} bytes, expected {GOVERNANCE_LEAF_CIPHERTEXT_LEN}",
            ciphertext.len()
        )));
    }

    let mut block = Vec::with_capacity(GOVERNANCE_LEAF_BLOCK_LEN);
    block.extend_from_slice(&GOVERNANCE_LEAF_BLOCK_MAGIC);
    block.push(GOVERNANCE_LEAF_BLOCK_VERSION);
    block.extend_from_slice(nonce);
    block.extend_from_slice(&CIPHERTEXT_LEN_FIELD.to_be_bytes());
    block.extend_from_slice(&ciphertext);
    Ok(block)
}

/// Checks one block's canonical encoding, decrypts it, and returns its body.
///
/// The checks, each failing closed with its own error, run in this order:
/// length at least the header, magic, version, `ciphertext_len` equal to
/// 32,784, total length equal to 21 + `ciphertext_len`, the AEAD tag,
/// `body_len` at most 32,764, and every padding byte zero (§7.3.1.1
/// "Canonical encoding"). The empty block returns an empty body.
///
/// # Errors
///
/// The [`GovernanceLeafBlockError`] variant of the first check that fails.
pub fn decode_block(
    crypto: &impl OpenMlsCrypto,
    key: &[u8; GOVERNANCE_LEAF_KEY_LEN],
    binding: &BlockBinding<'_>,
    block: &[u8],
) -> Result<Zeroizing<Vec<u8>>, GovernanceLeafBlockError> {
    let (header, ciphertext) = block
        .split_at_checked(GOVERNANCE_LEAF_HEADER_LEN)
        .ok_or(GovernanceLeafBlockError::WrongLength { len: block.len() })?;
    let (magic, rest) = header.split_at(4);
    if magic != GOVERNANCE_LEAF_BLOCK_MAGIC {
        return Err(GovernanceLeafBlockError::WrongMagic);
    }
    let (version, rest) = rest.split_at(1);
    if version != [GOVERNANCE_LEAF_BLOCK_VERSION] {
        return Err(GovernanceLeafBlockError::UnknownVersion(
            version.first().copied().unwrap_or_default(),
        ));
    }
    let (nonce, len_field) = rest.split_at(GOVERNANCE_LEAF_NONCE_LEN);
    let ciphertext_len = len_field
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| GovernanceLeafBlockError::WrongLength { len: block.len() })?;
    if ciphertext_len != CIPHERTEXT_LEN_FIELD {
        return Err(GovernanceLeafBlockError::WrongCiphertextLen(ciphertext_len));
    }
    if ciphertext.len() != GOVERNANCE_LEAF_CIPHERTEXT_LEN {
        return Err(GovernanceLeafBlockError::WrongLength { len: block.len() });
    }

    let aad = additional_data(binding)?;
    let plaintext = Zeroizing::new(
        crypto
            .aead_decrypt(AeadType::Aes128Gcm, key, ciphertext, nonce, &aad)
            .map_err(|_| GovernanceLeafBlockError::TagMismatch)?,
    );
    let (len_bytes, rest) = plaintext
        .split_at_checked(4)
        .ok_or(GovernanceLeafBlockError::TagMismatch)?;
    let body_len = len_bytes
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| GovernanceLeafBlockError::TagMismatch)?;
    let body_end = usize::try_from(body_len)
        .ok()
        .filter(|len| *len <= MAX_GOVERNANCE_LEAF_BODY_LEN)
        .ok_or(GovernanceLeafBlockError::BodyLenTooLarge(body_len))?;
    let (body, padding) = rest.split_at(body_end);
    if padding.iter().any(|b| *b != 0) {
        return Err(GovernanceLeafBlockError::NonZeroPadding);
    }
    Ok(Zeroizing::new(body.to_vec()))
}

/// Exports the block key of `group`'s current epoch for `context_id`.
///
/// The key comes from `MlsGroup::export_secret`, the epoch the group is in,
/// which before a merge is the sending epoch. The function takes the openmls
/// `GroupExport` secret by type, so the secret a staged commit exports,
/// which carries a different marker type, cannot reach it.
///
/// # Errors
///
/// [`GovernanceLeafBlockError::EmptyContextId`] or
/// [`GovernanceLeafBlockError::KeyExport`].
pub fn export_block_key(
    group: &MlsGroup,
    provider: &InMemoryMlsProvider,
    context_id: &str,
) -> Result<Zeroizing<[u8; GOVERNANCE_LEAF_KEY_LEN]>, GovernanceLeafBlockError> {
    if context_id.is_empty() {
        return Err(GovernanceLeafBlockError::EmptyContextId);
    }
    let secret = group
        .export_secret(
            provider.crypto(),
            GOVERNANCE_LEAF_EXPORTER_LABEL,
            context_id.as_bytes(),
            GOVERNANCE_LEAF_KEY_LEN,
        )
        .map_err(|e| GovernanceLeafBlockError::KeyExport(e.to_string()))?;
    key_from_group_export(&secret)
}

/// Copies a sending-epoch export into the zeroizing key buffer.
fn key_from_group_export(
    secret: &ExportedSecret<GroupExport>,
) -> Result<Zeroizing<[u8; GOVERNANCE_LEAF_KEY_LEN]>, GovernanceLeafBlockError> {
    let mut key = Zeroizing::new([0u8; GOVERNANCE_LEAF_KEY_LEN]);
    let bytes = secret.as_slice();
    if bytes.len() != GOVERNANCE_LEAF_KEY_LEN {
        return Err(GovernanceLeafBlockError::KeyExport(format!(
            "exporter returned {} bytes, expected {GOVERNANCE_LEAF_KEY_LEN}",
            bytes.len()
        )));
    }
    key.copy_from_slice(bytes);
    Ok(key)
}

/// Builds the block the local member puts on a Commit it is about to create:
/// bound to the group, its current epoch, and the member's own leaf, under a
/// fresh CSPRNG nonce. The key lives only inside this call.
pub(crate) fn seal_for_group(
    group: &MlsGroup,
    provider: &InMemoryMlsProvider,
    input: &GovernanceLeafBlockInput<'_>,
) -> Result<Vec<u8>, GovernanceLeafBlockError> {
    if input.body.len() > MAX_GOVERNANCE_LEAF_BODY_LEN {
        return Err(GovernanceLeafBlockError::BodyTooLarge {
            len: input.body.len(),
        });
    }
    let key = export_block_key(group, provider, input.context_id)?;
    let nonce: [u8; GOVERNANCE_LEAF_NONCE_LEN] = provider
        .rand()
        .random_array()
        .map_err(|e| GovernanceLeafBlockError::Random(e.to_string()))?;
    let binding = BlockBinding {
        group_id: group.group_id().as_slice(),
        epoch: group.epoch().as_u64(),
        sender_leaf_index: group.own_leaf_index().u32(),
    };
    encode_block(provider.crypto(), &key, &nonce, &binding, input.body)
}

/// Seals `input` as the block the local member would send in its current
/// epoch from its own leaf.
///
/// # Errors
///
/// [`MlsError::GroupDestroyed`], or [`MlsError::GovernanceLeafBlock`] with
/// the [`GovernanceLeafBlockError`] that stopped it.
pub fn seal_block(
    group: &ScpMlsGroup,
    input: &GovernanceLeafBlockInput<'_>,
) -> Result<Vec<u8>, MlsError> {
    let g = group.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
    Ok(seal_for_group(g, &group.provider, input)?)
}

/// Opens a block sent in `group`'s current epoch by the member at
/// `sender_leaf_index`, returning its body.
///
/// # Errors
///
/// [`MlsError::GroupDestroyed`], or [`MlsError::GovernanceLeafBlock`] with
/// the check that failed.
pub fn open_block(
    group: &ScpMlsGroup,
    context_id: &str,
    sender_leaf_index: u32,
    block: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MlsError> {
    let g = group.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
    Ok(open_for_group(
        g,
        &group.provider,
        context_id,
        sender_leaf_index,
        block,
    )?)
}

fn open_for_group(
    group: &MlsGroup,
    provider: &InMemoryMlsProvider,
    context_id: &str,
    sender_leaf_index: u32,
    block: &[u8],
) -> Result<Zeroizing<Vec<u8>>, GovernanceLeafBlockError> {
    let key = export_block_key(group, provider, context_id)?;
    let binding = BlockBinding {
        group_id: group.group_id().as_slice(),
        epoch: group.epoch().as_u64(),
        sender_leaf_index,
    };
    decode_block(provider.crypto(), &key, &binding, block)
}

/// A received Commit whose block decrypted, held before merge.
///
/// [`receive_commit`] returns it. The group is still in the sending epoch:
/// the caller authorizes the body against the pre-Commit state, then calls
/// [`Self::merge`] or [`Self::discard`]. Dropping it discards it.
pub struct StagedGovernanceCommit {
    staged: Box<StagedCommit>,
    group_id: Vec<u8>,
    sending_epoch: u64,
    sender_leaf_index: LeafNodeIndex,
    sender_did: String,
    pre_commit_tree: Vec<Member>,
    body: Zeroizing<Vec<u8>>,
    added: Vec<AdmittedLeaf>,
    members: MemberLeaves,
}

impl std::fmt::Debug for StagedGovernanceCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The body is confidential (spec 09 §9.10.1); only its length shows.
        f.debug_struct("StagedGovernanceCommit")
            .field("sending_epoch", &self.sending_epoch)
            .field("sender_leaf_index", &self.sender_leaf_index)
            .field("sender_did", &self.sender_did)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl StagedGovernanceCommit {
    /// The epoch the Commit was sent in, which the group is still in.
    #[must_use]
    pub const fn sending_epoch(&self) -> u64 {
        self.sending_epoch
    }

    /// The committer's leaf index in the sending epoch's tree.
    #[must_use]
    pub const fn sender_leaf_index(&self) -> LeafNodeIndex {
        self.sender_leaf_index
    }

    /// The DID the committer's verified credential names.
    #[must_use]
    pub fn sender_did(&self) -> &str {
        &self.sender_did
    }

    /// The sending epoch's tree, read before the merge: the committer's leaf
    /// is its leaf before the Commit.
    #[must_use]
    pub fn pre_commit_tree(&self) -> &[Member] {
        &self.pre_commit_tree
    }

    /// The decrypted block body; empty for the empty block.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The Add leaves the Commit admits, in proposal order.
    #[must_use]
    pub fn added(&self) -> &[AdmittedLeaf] {
        &self.added
    }

    /// The tree's leaves after the Commit, computed before the merge.
    #[must_use]
    pub const fn members(&self) -> &MemberLeaves {
        &self.members
    }

    /// The openmls staged Commit, for inspection before the merge.
    #[must_use]
    pub fn staged_commit(&self) -> &StagedCommit {
        &self.staged
    }

    /// Merges the Commit, advancing `group` to the next epoch, and returns the
    /// tree's leaves after it.
    ///
    /// # Errors
    ///
    /// [`MlsError::GroupDestroyed`]; [`MlsError::StagedCommitMismatch`] when
    /// `group` is not the group, or not in the epoch, the Commit was staged
    /// for (another Commit merged first); or
    /// [`MlsError::CommitProcessingFailed`] when openmls cannot merge.
    pub fn merge(self, group: &mut ScpMlsGroup) -> Result<MemberLeaves, MlsError> {
        let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
        let group_epoch = g.epoch().as_u64();
        if g.group_id().as_slice() != self.group_id.as_slice() || group_epoch != self.sending_epoch
        {
            return Err(MlsError::StagedCommitMismatch {
                staged_epoch: self.sending_epoch,
                group_epoch,
            });
        }
        g.merge_staged_commit(&group.provider, *self.staged)
            .map_err(|e| MlsError::CommitProcessingFailed(format!("merging staged commit: {e}")))?;
        Ok(self.members)
    }

    /// Drops the Commit unmerged. The group stays in the sending epoch and
    /// processes the next valid Commit of that epoch.
    pub fn discard(self) {
        drop(self);
    }
}

/// Phase one of receiving a Commit: verify and decrypt the frame, admit the
/// Commit's leaves, and decrypt its governance leaf block, without merging.
///
/// The frame must be a Commit; another content type is refused before openmls
/// processes it, so no message key is consumed. openmls verifies the frame's
/// signature and AEAD, which cover `authenticated_data`. The block key is
/// exported from the group, which is still in the sending epoch, so the key
/// is the sending epoch's. The pre-Commit tree is read before anything merges.
///
/// # Errors
///
/// - [`MlsError::GroupDestroyed`];
/// - [`MlsError::DeserializationFailed`] or [`MlsError::DecryptionFailed`]
///   when the frame does not parse or verify;
/// - [`MlsError::NotACommit`] for any other content type;
/// - [`MlsError::CannotDecryptOwnMessage`] for an echo of this member's own
///   Commit;
/// - any admission error of [`crate::admission`];
/// - [`MlsError::GovernanceLeafBlock`] when the block fails a canonical check
///   or does not decrypt.
///
/// Every error drops the staged Commit unmerged and returns no body bytes.
pub fn receive_commit(
    group: &mut ScpMlsGroup,
    context_id: &str,
    frame: &[u8],
) -> Result<StagedGovernanceCommit, MlsError> {
    if context_id.is_empty() {
        return Err(GovernanceLeafBlockError::EmptyContextId.into());
    }
    let message_in = crate::wire::parse_mls_message_in(frame)?;
    let protocol_message: ProtocolMessage = message_in
        .try_into_protocol_message()
        .map_err(|e| MlsError::DecryptionFailed(format!("extracting protocol message: {e}")))?;
    if protocol_message.content_type() != ContentType::Commit {
        return Err(MlsError::NotACommit);
    }

    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    let processed = crate::encrypt::process_inbound(g, &group.provider, protocol_message)?;
    let g = group.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
    let (sender_leaf_index, sender_did) =
        crate::encrypt::sender_member(g, &group.provider, &processed)?;
    let sending_epoch = processed.epoch().as_u64();
    let aad = processed.aad().to_vec();

    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        return Err(MlsError::NotACommit);
    };

    let admission = admit_staged_commit(g, &staged, sender_leaf_index, LifetimeCheck::Receiver)?;
    let body = open_for_group(
        g,
        &group.provider,
        context_id,
        sender_leaf_index.u32(),
        &aad,
    )?;

    Ok(StagedGovernanceCommit {
        staged,
        group_id: g.group_id().as_slice().to_vec(),
        sending_epoch,
        sender_leaf_index,
        sender_did,
        pre_commit_tree: g.members().collect(),
        body,
        added: admission.added,
        members: admission.members,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use openmls::prelude::tls_codec::Serialize as _;
    use openmls::prelude::{KeyPackage, LeafNodeIndex, LeafNodeParameters, MlsGroupJoinConfig};
    use openmls_basic_credential::SignatureKeyPair;
    use scp_clock::SystemClock;
    use scp_crypto::p256::testing::uncompressed_point_for;

    use super::*;
    use crate::credential::ScpCredential;
    use crate::encrypt::{decrypt, encrypt, serialize_ciphertext};
    use crate::group::{
        add_member, build_own_commit, create_group, generate_key_package, join_group,
        remove_member, scp_join_config, set_padding,
    };
    use crate::ratchet::{propose_update, propose_update_with_wrapping_key};

    const CTX: &str = "4f1c0e9a5b7d3e2f";

    fn cred(name: &str) -> ScpCredential {
        ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_did::SigningKeyId::Active,
        )
        .unwrap()
    }

    fn wrapping_key(name: &str) -> [u8; 65] {
        uncompressed_point_for(&cred(name).did)
    }

    const fn empty() -> GovernanceLeafBlockInput<'static> {
        GovernanceLeafBlockInput::empty(CTX)
    }

    const fn with_body(body: &[u8]) -> GovernanceLeafBlockInput<'_> {
        GovernanceLeafBlockInput {
            context_id: CTX,
            body,
        }
    }

    /// A body of `len` bytes, none of them zero.
    fn body(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap() + 1)
            .collect()
    }

    fn kp(name: &str) -> (KeyPackage, SignatureKeyPair, InMemoryMlsProvider) {
        let (bundle, signer, provider) =
            generate_key_package(&cred(name), &wrapping_key(name), &SystemClock).unwrap();
        (bundle.key_package().clone(), signer, provider)
    }

    /// Alice created the group and added Bob, then Carol; Bob processed the
    /// add of Carol through the two-phase receive. All three sit at epoch 2.
    struct Fixture {
        alice: ScpMlsGroup,
        bob: ScpMlsGroup,
        carol: ScpMlsGroup,
    }

    fn fixture() -> Fixture {
        let mut alice = create_group(&cred("alice"), &wrapping_key("alice"), &SystemClock).unwrap();
        let (bob_kp, bob_signer, bob_provider) = kp("bob");
        let add_bob = add_member(&mut alice, bob_kp.into(), &empty(), &SystemClock).unwrap();
        let mut bob = join_group(&add_bob.welcome, bob_provider, bob_signer, &SystemClock).unwrap();
        let (carol_kp, carol_signer, carol_provider) = kp("carol");
        let add_carol = add_member(&mut alice, carol_kp.into(), &empty(), &SystemClock).unwrap();
        let carol = join_group(
            &add_carol.welcome,
            carol_provider,
            carol_signer,
            &SystemClock,
        )
        .unwrap();
        receive_commit(&mut bob, CTX, &add_carol.commit_bytes)
            .unwrap()
            .merge(&mut bob)
            .unwrap();
        for g in [&alice, &bob, &carol] {
            assert_eq!(g.epoch().unwrap(), 2);
        }
        Fixture { alice, bob, carol }
    }

    fn inner(group: &ScpMlsGroup) -> &MlsGroup {
        group.group.as_ref().unwrap()
    }

    fn own_index(group: &ScpMlsGroup) -> u32 {
        inner(group).own_leaf_index().u32()
    }

    fn config(group: &ScpMlsGroup) -> MlsGroupJoinConfig {
        inner(group).configuration().clone()
    }

    // TLS reading of an MLSMessage carrying a PrivateMessage (RFC 9420 §6.3).

    fn varint(bytes: &[u8], at: &mut usize) -> usize {
        let first = bytes[*at];
        let width = 1usize << (first >> 6);
        assert!(width <= 4, "varint prefix 11 is invalid");
        let mut value = usize::from(first & 0x3f);
        for k in 1..width {
            value = (value << 8) | usize::from(bytes[*at + k]);
        }
        *at += width;
        value
    }

    fn opaque<'a>(bytes: &'a [u8], at: &mut usize) -> &'a [u8] {
        let len = varint(bytes, at);
        let out = &bytes[*at..*at + len];
        *at += len;
        out
    }

    const fn varint_len(len: usize) -> usize {
        if len < 1 << 6 {
            1
        } else if len < 1 << 14 {
            2
        } else {
            4
        }
    }

    struct PrivateFrame {
        epoch: u64,
        content_type: u8,
        authenticated_data: Vec<u8>,
        ciphertext_len: usize,
    }

    fn parse_private(bytes: &[u8]) -> PrivateFrame {
        assert_eq!(bytes[..2], [0, 1], "mls10");
        assert_eq!(bytes[2..4], [0, 2], "mls_private_message");
        let mut at = 4;
        let _group_id = opaque(bytes, &mut at);
        let epoch = u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
        at += 8;
        let content_type = bytes[at];
        at += 1;
        let authenticated_data = opaque(bytes, &mut at).to_vec();
        let _encrypted_sender_data = opaque(bytes, &mut at);
        let ciphertext_len = opaque(bytes, &mut at).len();
        assert_eq!(at, bytes.len(), "trailing bytes after the PrivateMessage");
        PrivateFrame {
            epoch,
            content_type,
            authenticated_data,
            ciphertext_len,
        }
    }

    /// Asserts a Commit frame's `ciphertext` is a non-zero multiple of 4,096
    /// and its `authenticated_data` is one block.
    fn assert_padded_commit(commit: &[u8]) {
        let frame = parse_private(commit);
        assert_eq!(frame.content_type, 3, "commit");
        assert_eq!(frame.authenticated_data.len(), GOVERNANCE_LEAF_BLOCK_LEN);
        assert!(frame.ciphertext_len > 0);
        assert_eq!(
            frame.ciphertext_len % COMMIT_PADDING_MULTIPLE,
            0,
            "commit ciphertext {} is not a multiple of {COMMIT_PADDING_MULTIPLE}",
            frame.ciphertext_len
        );
    }

    /// Sends a 100-byte application message from `group` and asserts it
    /// carries no MLS padding: its `ciphertext` is the 16-byte tag plus the
    /// unpadded `PrivateMessageContent`, `application_data<V>` then
    /// `signature<V>`. A P-256 ECDSA signature is DER and varies in length,
    /// 8 to 72 bytes, so `signature<V>` with its varint prefix is bounded,
    /// 9 to 74 bytes, rather than known.
    fn assert_unpadded_application(group: &mut ScpMlsGroup) {
        const APP: usize = 100;
        let message = encrypt(group, &[7u8; APP]).unwrap();
        let frame = parse_private(&serialize_ciphertext(&message).unwrap());
        assert_eq!(frame.content_type, 1, "application");
        let signature = frame
            .ciphertext_len
            .checked_sub(GOVERNANCE_LEAF_TAG_LEN + varint_len(APP) + APP)
            .expect("ciphertext shorter than its content");
        let bounds = (1 + 8)..=(varint_len(72) + 72);
        assert!(
            bounds.contains(&signature),
            "application ciphertext {} leaves {signature} bytes for signature<V>: padded",
            frame.ciphertext_len
        );
    }

    fn fixed_binding() -> BlockBinding<'static> {
        BlockBinding {
            group_id: b"group-g",
            epoch: 7,
            sender_leaf_index: 3,
        }
    }

    const KEY: [u8; 16] = [0x11; 16];
    const NONCE: [u8; 12] = [0x22; 12];

    fn encode(body: &[u8]) -> Vec<u8> {
        let provider = InMemoryMlsProvider::default();
        encode_block(provider.crypto(), &KEY, &NONCE, &fixed_binding(), body).unwrap()
    }

    fn decode_with(
        binding: &BlockBinding<'_>,
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, GovernanceLeafBlockError> {
        let provider = InMemoryMlsProvider::default();
        decode_block(provider.crypto(), &KEY, binding, block)
    }

    fn decode(block: &[u8]) -> Result<Zeroizing<Vec<u8>>, GovernanceLeafBlockError> {
        decode_with(&fixed_binding(), block)
    }

    // One size for every block.

    #[test]
    fn every_block_is_32805_bytes_with_ciphertext_len_32784() {
        for len in [0, 1, MAX_GOVERNANCE_LEAF_BODY_LEN] {
            let b = body(len);
            let block = encode(&b);
            assert_eq!(block.len(), 32_805, "body of {len}");
            assert_eq!(&block[..4], b"SCPG");
            assert_eq!(block[4], 1);
            assert_eq!(block[5..17], NONCE);
            assert_eq!(block[17..21], 32_784u32.to_be_bytes());
            assert_eq!(decode(&block).unwrap().as_slice(), b.as_slice());
        }
    }

    #[test]
    fn a_body_of_32765_bytes_is_refused_and_builds_no_commit() {
        let oversize = body(MAX_GOVERNANCE_LEAF_BODY_LEN + 1);
        let provider = InMemoryMlsProvider::default();
        assert_eq!(
            encode_block(provider.crypto(), &KEY, &NONCE, &fixed_binding(), &oversize),
            Err(GovernanceLeafBlockError::BodyTooLarge { len: 32_765 })
        );

        let mut f = fixture();
        let before = config(&f.alice);
        let Err(err) = propose_update(&mut f.alice, &with_body(&oversize), &SystemClock) else {
            panic!("a 32,765-byte body built a Commit");
        };
        assert!(
            matches!(
                err,
                MlsError::GovernanceLeafBlock(GovernanceLeafBlockError::BodyTooLarge {
                    len: 32_765
                })
            ),
            "{err:?}"
        );
        assert_eq!(f.alice.epoch().unwrap(), 2);
        assert!(inner(&f.alice).pending_commit().is_none());
        assert_eq!(config(&f.alice), before);
    }

    // Commit padding; application messages unpadded.

    #[test]
    fn an_empty_block_key_update_commit_is_padded_and_application_messages_are_not() {
        let mut f = fixture();
        assert_unpadded_application(&mut f.alice);
        let update = propose_update(&mut f.alice, &empty(), &SystemClock).unwrap();
        assert_padded_commit(&update.commit_bytes);
        assert_unpadded_application(&mut f.alice);
    }

    #[test]
    fn a_leaf_bearing_commit_is_padded_and_application_messages_are_not() {
        let mut f = fixture();
        assert_unpadded_application(&mut f.alice);
        let b = body(15_616);
        let update = propose_update_with_wrapping_key(
            &mut f.alice,
            &wrapping_key("alice"),
            &with_body(&b),
            &SystemClock,
        )
        .unwrap();
        assert_padded_commit(&update.commit_bytes);
        assert_unpadded_application(&mut f.alice);
    }

    #[test]
    fn an_add_member_commit_is_padded_and_application_messages_are_not() {
        let mut f = fixture();
        assert_unpadded_application(&mut f.alice);
        let (dave_kp, _, _) = kp("dave");
        let add = add_member(&mut f.alice, dave_kp.into(), &empty(), &SystemClock).unwrap();
        assert_padded_commit(&add.commit_bytes);
        assert_unpadded_application(&mut f.alice);
    }

    #[test]
    fn a_group_loaded_with_padding_4096_persisted_sends_unpadded_application_messages() {
        let mut alice = fixture().alice;
        {
            let g = alice.group.as_mut().unwrap();
            set_padding(g, &alice.provider, COMMIT_PADDING_MULTIPLE).unwrap();
        }
        assert_eq!(config(&alice).padding_size(), COMMIT_PADDING_MULTIPLE);
        let blob = alice.serialize_state().unwrap();
        let mut loaded = ScpMlsGroup::deserialize_state(&blob).unwrap();
        assert_unpadded_application(&mut loaded);
    }

    // Commit padding changes no other setting.

    #[test]
    fn the_configuration_after_an_empty_block_commit_equals_the_one_before() {
        let mut f = fixture();
        let before = config(&f.alice);
        assert_eq!(before, scp_join_config(0));
        propose_update(&mut f.alice, &empty(), &SystemClock).unwrap();
        assert_eq!(config(&f.alice), before);
    }

    #[test]
    fn the_configuration_after_a_leaf_bearing_commit_equals_the_one_before() {
        let mut f = fixture();
        let before = config(&f.alice);
        let b = body(4_000);
        let carol = LeafNodeIndex::new(own_index(&f.carol));
        remove_member(&mut f.alice, carol, &with_body(&b), &SystemClock).unwrap();
        assert_eq!(config(&f.alice), before);
    }

    #[test]
    fn the_configuration_after_a_load_equals_the_one_before() {
        let mut bob = fixture().bob;
        let before = config(&bob);
        assert_eq!(before, scp_join_config(0));
        {
            let g = bob.group.as_mut().unwrap();
            set_padding(g, &bob.provider, COMMIT_PADDING_MULTIPLE).unwrap();
        }
        let state = bob.serialize_state().unwrap();
        let loaded = ScpMlsGroup::deserialize_state(&state).unwrap();
        assert_eq!(config(&loaded), before);
    }

    // Canonical-encoding checks.

    /// A block around an arbitrary 32,768-byte plaintext, sealed under the
    /// fixed key, so the checks after the tag can be reached.
    fn block_around(plaintext: &[u8]) -> Vec<u8> {
        assert_eq!(plaintext.len(), GOVERNANCE_LEAF_PLAINTEXT_LEN);
        let aad = additional_data(&fixed_binding()).unwrap();
        let provider = InMemoryMlsProvider::default();
        let ciphertext = provider
            .crypto()
            .aead_encrypt(AeadType::Aes128Gcm, &KEY, plaintext, &NONCE, &aad)
            .unwrap();
        let mut block = Vec::new();
        block.extend_from_slice(b"SCPG");
        block.push(1);
        block.extend_from_slice(&NONCE);
        block.extend_from_slice(&32_784u32.to_be_bytes());
        block.extend_from_slice(&ciphertext);
        block
    }

    #[test]
    fn decode_refuses_wrong_magic() {
        let mut block = encode(&body(10));
        block[0] = b'X';
        assert_eq!(decode(&block), Err(GovernanceLeafBlockError::WrongMagic));
    }

    #[test]
    fn decode_refuses_an_unknown_version() {
        let mut block = encode(&body(10));
        block[4] = 2;
        assert_eq!(
            decode(&block),
            Err(GovernanceLeafBlockError::UnknownVersion(2))
        );
    }

    #[test]
    fn decode_refuses_a_ciphertext_len_other_than_32784() {
        let mut block = encode(&body(10));
        block[17..21].copy_from_slice(&32_783u32.to_be_bytes());
        assert_eq!(
            decode(&block),
            Err(GovernanceLeafBlockError::WrongCiphertextLen(32_783))
        );
    }

    #[test]
    fn decode_refuses_a_length_other_than_21_plus_ciphertext_len() {
        let block = encode(&body(10));
        let mut long = block.clone();
        long.push(0);
        assert_eq!(
            decode(&long),
            Err(GovernanceLeafBlockError::WrongLength { len: 32_806 })
        );
        assert_eq!(
            decode(&block[..block.len() - 1]),
            Err(GovernanceLeafBlockError::WrongLength { len: 32_804 })
        );
        assert_eq!(
            decode(&block[..20]),
            Err(GovernanceLeafBlockError::WrongLength { len: 20 })
        );
    }

    #[test]
    fn decode_refuses_a_tag_that_does_not_verify() {
        let mut block = encode(&body(10));
        let last = block.len() - 1;
        block[last] ^= 1;
        assert_eq!(decode(&block), Err(GovernanceLeafBlockError::TagMismatch));
    }

    #[test]
    fn decode_refuses_a_non_zero_padding_byte() {
        let mut plaintext = vec![0u8; GOVERNANCE_LEAF_PLAINTEXT_LEN];
        plaintext[..4].copy_from_slice(&3u32.to_be_bytes());
        plaintext[4..7].copy_from_slice(b"abc");
        assert_eq!(
            decode(&block_around(&plaintext)).unwrap().as_slice(),
            b"abc"
        );
        plaintext[GOVERNANCE_LEAF_PLAINTEXT_LEN - 1] = 1;
        assert_eq!(
            decode(&block_around(&plaintext)),
            Err(GovernanceLeafBlockError::NonZeroPadding)
        );
    }

    #[test]
    fn decode_refuses_a_body_len_above_32764() {
        let mut plaintext = vec![0u8; GOVERNANCE_LEAF_PLAINTEXT_LEN];
        plaintext[..4].copy_from_slice(&32_764u32.to_be_bytes());
        assert_eq!(decode(&block_around(&plaintext)).unwrap().len(), 32_764);
        plaintext[..4].copy_from_slice(&32_765u32.to_be_bytes());
        assert_eq!(
            decode(&block_around(&plaintext)),
            Err(GovernanceLeafBlockError::BodyLenTooLarge(32_765))
        );
    }

    #[test]
    fn the_empty_block_decodes_to_an_empty_body() {
        assert!(decode(&encode(&[])).unwrap().is_empty());
    }

    // The additional data binds group, epoch, and sender leaf.

    #[test]
    fn a_block_for_another_group_does_not_decrypt() {
        let binding = BlockBinding {
            group_id: b"group-h",
            ..fixed_binding()
        };
        assert_eq!(
            decode_with(&binding, &encode(&body(10))),
            Err(GovernanceLeafBlockError::TagMismatch)
        );
    }

    #[test]
    fn a_block_for_another_epoch_does_not_decrypt() {
        let binding = BlockBinding {
            epoch: 8,
            ..fixed_binding()
        };
        assert_eq!(
            decode_with(&binding, &encode(&body(10))),
            Err(GovernanceLeafBlockError::TagMismatch)
        );
    }

    #[test]
    fn a_block_for_another_sender_leaf_does_not_decrypt() {
        let binding = BlockBinding {
            sender_leaf_index: 4,
            ..fixed_binding()
        };
        assert_eq!(
            decode_with(&binding, &encode(&body(10))),
            Err(GovernanceLeafBlockError::TagMismatch)
        );
    }

    // The exporter key.

    #[test]
    fn two_members_of_one_epoch_open_each_others_blocks() {
        let f = fixture();
        let a = body(300);
        let b = body(17);
        let from_alice = seal_block(&f.alice, &with_body(&a)).unwrap();
        let from_bob = seal_block(&f.bob, &with_body(&b)).unwrap();
        assert_eq!(
            open_block(&f.bob, CTX, own_index(&f.alice), &from_alice)
                .unwrap()
                .as_slice(),
            a.as_slice()
        );
        assert_eq!(
            open_block(&f.alice, CTX, own_index(&f.bob), &from_bob)
                .unwrap()
                .as_slice(),
            b.as_slice()
        );
        // The context id is the exporter context: another one's key fails.
        assert!(matches!(
            open_block(&f.bob, "another-context", own_index(&f.alice), &from_alice),
            Err(MlsError::GovernanceLeafBlock(
                GovernanceLeafBlockError::TagMismatch
            ))
        ));
    }

    #[test]
    fn a_block_of_epoch_n_does_not_open_under_the_key_of_epoch_n_plus_1() {
        let mut f = fixture();
        let block = seal_block(&f.alice, &with_body(&body(9))).unwrap();
        let alice = own_index(&f.alice);
        let group_id = inner(&f.bob).group_id().as_slice().to_vec();
        let update = propose_update(&mut f.alice, &empty(), &SystemClock).unwrap();
        receive_commit(&mut f.bob, CTX, &update.commit_bytes)
            .unwrap()
            .merge(&mut f.bob)
            .unwrap();
        assert_eq!(f.bob.epoch().unwrap(), 3);
        // Epoch 3's key under epoch 2's binding: only the key differs.
        let key_3 = export_block_key(inner(&f.bob), &f.bob.provider, CTX).unwrap();
        let binding_2 = BlockBinding {
            group_id: &group_id,
            epoch: 2,
            sender_leaf_index: alice,
        };
        assert_eq!(
            decode_block(f.bob.provider.crypto(), &key_3, &binding_2, &block),
            Err(GovernanceLeafBlockError::TagMismatch)
        );
        // Carol, still at epoch 2, opens it under epoch 2's key.
        let key_2 = export_block_key(inner(&f.carol), &f.carol.provider, CTX).unwrap();
        assert_eq!(
            decode_block(f.carol.provider.crypto(), &key_2, &binding_2, &block)
                .unwrap()
                .len(),
            9
        );
    }

    /// Every `.rs` file under `src/`, with its path.
    fn crate_sources() -> Vec<(std::path::PathBuf, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    out.push((path, text));
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        assert!(out.len() > 10, "found {} source files", out.len());
        out
    }

    /// The staged commit's `export_secret` gives the new epoch's secret, so the
    /// block key never comes from it. The one exporter call in `scp-mls` is
    /// the one in [`export_block_key`], on the `MlsGroup`, and no source names
    /// the staged-commit export marker type.
    #[test]
    fn staged_commit_export_secret_has_no_call_site() {
        let call = concat!(".export_", "secret(");
        let marker = concat!("StagedCommit", "Export");
        let qualified = concat!("StagedCommit::", "export_secret");
        let mut calls = Vec::new();
        for (path, text) in crate_sources() {
            assert!(!text.contains(marker), "{} names {marker}", path.display());
            assert!(
                !text.contains(qualified),
                "{} calls {qualified}",
                path.display()
            );
            for (at, _) in text.match_indices(call) {
                calls.push((path.clone(), text[..at].trim_end().to_owned()));
            }
        }
        let paths: Vec<_> = calls.iter().map(|c| c.0.display().to_string()).collect();
        assert_eq!(calls.len(), 1, "exporter calls: {paths:?}");
        let (path, before) = &calls[0];
        assert!(path.ends_with("governance_leaf_block.rs"));
        assert!(
            before.ends_with("group"),
            "the one exporter call's receiver is the MlsGroup"
        );
    }

    // The key is zeroized and local.

    /// The block key is a `Zeroizing` value: `export_block_key` returns no
    /// other type, and the committer path holds it only inside
    /// `seal_for_group`, which returns before the Commit is built.
    #[test]
    fn the_block_key_is_held_in_zeroizing() {
        type Exporter =
            fn(
                &MlsGroup,
                &InMemoryMlsProvider,
                &str,
            )
                -> Result<Zeroizing<[u8; GOVERNANCE_LEAF_KEY_LEN]>, GovernanceLeafBlockError>;
        let exporter: Exporter = export_block_key;
        let f = fixture();
        assert_eq!(
            exporter(inner(&f.alice), &f.alice.provider, CTX)
                .unwrap()
                .len(),
            16
        );
        assert_eq!(
            exporter(inner(&f.alice), &f.alice.provider, ""),
            Err(GovernanceLeafBlockError::EmptyContextId)
        );
    }

    // Committer entry points and the two-phase receive.

    fn leaf_of(tree: &[Member], index: u32) -> Member {
        tree.iter()
            .find(|m| m.index.u32() == index)
            .cloned()
            .expect("leaf in tree")
    }

    /// Bob receives `commit` from Alice; checks the body, sending epoch,
    /// sender, and pre-Commit tree the two-phase receive returns before any
    /// merge; and returns the staged Commit.
    fn receive_and_check(
        f: &mut Fixture,
        commit: &[u8],
        expected_body: &[u8],
    ) -> StagedGovernanceCommit {
        let alice = own_index(&f.alice);
        let tree_before: Vec<Member> = inner(&f.bob).members().collect();
        let staged = receive_commit(&mut f.bob, CTX, commit).unwrap();
        assert_eq!(staged.body(), expected_body);
        assert_eq!(staged.sending_epoch(), 2);
        assert_eq!(staged.sender_leaf_index().u32(), alice);
        assert_eq!(staged.sender_did(), cred("alice").did);
        assert_eq!(staged.pre_commit_tree(), tree_before.as_slice());
        assert_eq!(f.bob.epoch().unwrap(), 2, "nothing merged");
        staged
    }

    /// After the merge, the committer's leaf differs from the one in the
    /// pre-Commit view, so the view held the leaf before the Commit.
    fn assert_view_was_pre_commit(f: &Fixture, staged_tree: &[Member]) {
        let alice = own_index(&f.alice);
        let after: Vec<Member> = inner(&f.bob).members().collect();
        assert_ne!(
            leaf_of(staged_tree, alice).encryption_key,
            leaf_of(&after, alice).encryption_key
        );
    }

    #[test]
    fn an_add_commit_carries_the_block_to_the_two_phase_receive() {
        let mut f = fixture();
        let b = body(1_234);
        let (dave_kp, _, _) = kp("dave");
        let add = add_member(&mut f.alice, dave_kp.into(), &with_body(&b), &SystemClock).unwrap();
        let staged = receive_and_check(&mut f, &add.commit_bytes, &b);
        assert_eq!(staged.pre_commit_tree().len(), 3);
        assert_eq!(staged.added().len(), 1);
        staged.merge(&mut f.bob).unwrap();
        assert_eq!(f.bob.epoch().unwrap(), 3);
        assert_eq!(inner(&f.bob).members().count(), 4);
    }

    #[test]
    fn a_remove_commit_carries_the_block_to_the_two_phase_receive() {
        let mut f = fixture();
        let b = body(77);
        let carol = LeafNodeIndex::new(own_index(&f.carol));
        let remove = remove_member(&mut f.alice, carol, &with_body(&b), &SystemClock).unwrap();
        let staged = receive_and_check(&mut f, &remove.commit_bytes, &b);
        let tree = staged.pre_commit_tree().to_vec();
        assert!(tree.iter().any(|m| m.index == carol));
        staged.merge(&mut f.bob).unwrap();
        assert_eq!(f.bob.epoch().unwrap(), 3);
        assert_view_was_pre_commit(&f, &tree);
    }

    #[test]
    fn an_update_path_commit_without_add_or_remove_carries_the_block() {
        let mut f = fixture();
        let b = body(15_616);
        let update = propose_update_with_wrapping_key(
            &mut f.alice,
            &wrapping_key("alice"),
            &with_body(&b),
            &SystemClock,
        )
        .unwrap();
        let staged = receive_and_check(&mut f, &update.commit_bytes, &b);
        assert!(staged.added().is_empty());
        let tree = staged.pre_commit_tree().to_vec();
        staged.merge(&mut f.bob).unwrap();
        assert_view_was_pre_commit(&f, &tree);
    }

    #[test]
    fn a_self_update_commit_carries_the_block() {
        let mut f = fixture();
        let b = body(40);
        let update = propose_update(&mut f.alice, &with_body(&b), &SystemClock).unwrap();
        let staged = receive_and_check(&mut f, &update.commit_bytes, &b);
        let tree = staged.pre_commit_tree().to_vec();
        let members = staged.merge(&mut f.bob).unwrap();
        assert_eq!(members, update.members);
        assert_view_was_pre_commit(&f, &tree);
    }

    #[test]
    fn the_two_phase_receive_refuses_an_application_message_unprocessed() {
        let mut f = fixture();
        let message = serialize_ciphertext(&encrypt(&mut f.alice, b"hello").unwrap()).unwrap();
        assert!(matches!(
            receive_commit(&mut f.bob, CTX, &message),
            Err(MlsError::NotACommit)
        ));
        // Refused before openmls processed it, so Bob still decrypts it.
        assert_eq!(decrypt(&mut f.bob, &message).unwrap(), b"hello");
    }

    // Tamper, discard, and the next Commit of the epoch.

    #[test]
    fn a_flipped_block_byte_is_rejected_with_no_body_and_the_epoch_continues() {
        let mut f = fixture();
        let update = propose_update(&mut f.alice, &with_body(&body(40)), &SystemClock).unwrap();
        assert_eq!(parse_private(&update.commit_bytes).epoch, 2);
        let block_at = update
            .commit_bytes
            .windows(4)
            .position(|w| w == b"SCPG")
            .unwrap();
        let mut tampered = update.commit_bytes;
        tampered[block_at + 100] ^= 1;
        assert!(receive_commit(&mut f.bob, CTX, &tampered).is_err());
        assert_eq!(f.bob.epoch().unwrap(), 2);

        let carol = propose_update(&mut f.carol, &empty(), &SystemClock).unwrap();
        receive_commit(&mut f.bob, CTX, &carol.commit_bytes)
            .unwrap()
            .merge(&mut f.bob)
            .unwrap();
        assert_eq!(f.bob.epoch().unwrap(), 3);
    }

    /// A committer that signs a Commit around a block with one ciphertext
    /// byte flipped gets past openmls's signature and AEAD; the block check
    /// rejects it, returns no body, and merges nothing.
    #[test]
    fn a_signed_commit_with_a_corrupt_block_is_rejected_by_the_block_check() {
        let mut f = fixture();
        let mut block = seal_block(&f.alice, &empty()).unwrap();
        block[GOVERNANCE_LEAF_HEADER_LEN + 5] ^= 1;
        let commit = build_own_commit(&mut f.alice, block, |g, provider, signer| {
            g.self_update(provider, signer, LeafNodeParameters::default())
                .map_err(|e| MlsError::UpdateFailed(e.to_string()))
        })
        .unwrap()
        .into_commit()
        .tls_serialize_detached()
        .unwrap();
        let err = receive_commit(&mut f.bob, CTX, &commit).unwrap_err();
        assert!(
            matches!(
                err,
                MlsError::GovernanceLeafBlock(GovernanceLeafBlockError::TagMismatch)
            ),
            "{err:?}"
        );
        assert_eq!(f.bob.epoch().unwrap(), 2);

        let carol = propose_update(&mut f.carol, &empty(), &SystemClock).unwrap();
        receive_commit(&mut f.bob, CTX, &carol.commit_bytes)
            .unwrap()
            .merge(&mut f.bob)
            .unwrap();
        assert_eq!(f.bob.epoch().unwrap(), 3);
    }

    #[test]
    fn after_a_discard_the_group_processes_the_next_commit_of_the_epoch() {
        let mut f = fixture();
        let alice = propose_update(&mut f.alice, &empty(), &SystemClock).unwrap();
        let b = body(5);
        let carol = propose_update(&mut f.carol, &with_body(&b), &SystemClock).unwrap();
        receive_commit(&mut f.bob, CTX, &alice.commit_bytes)
            .unwrap()
            .discard();
        assert_eq!(f.bob.epoch().unwrap(), 2);
        let staged = receive_commit(&mut f.bob, CTX, &carol.commit_bytes).unwrap();
        assert_eq!(staged.body(), b.as_slice());
        staged.merge(&mut f.bob).unwrap();
        assert_eq!(f.bob.epoch().unwrap(), 3);
    }

    #[test]
    fn a_staged_commit_does_not_merge_after_another_commit_of_its_epoch() {
        let mut f = fixture();
        let alice = propose_update(&mut f.alice, &empty(), &SystemClock).unwrap();
        let carol = propose_update(&mut f.carol, &empty(), &SystemClock).unwrap();
        let first = receive_commit(&mut f.bob, CTX, &alice.commit_bytes).unwrap();
        let second = receive_commit(&mut f.bob, CTX, &carol.commit_bytes).unwrap();
        first.merge(&mut f.bob).unwrap();
        assert!(matches!(
            second.merge(&mut f.bob),
            Err(MlsError::StagedCommitMismatch {
                staged_epoch: 2,
                group_epoch: 3
            })
        ));
    }
}
