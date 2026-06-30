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
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use crate::error::MlsError;
use crate::group::ScpMlsGroup;

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
    // OpenMLS may panic on AEAD decryption failure for tampered ciphertexts
    // (e.g., corrupted authentication tags). We guard against this with
    // catch_unwind to convert the panic into an MlsError::DecryptionFailed,
    // preventing a malicious relay from crashing the client process (DoS).
    //
    // NOTE (ADR-057 §Prereq-4): `catch_unwind` is INERT under the wasm default
    // `panic=abort` — a single attacker-delivered tampered ciphertext would
    // abort the whole tab (a remote-triggerable availability hit, worse than
    // native). The browser target MUST therefore build with `panic=unwind`, and
    // the wasm unwind-ABI panic-safety of openmls/RustCrypto across these
    // `AssertUnwindSafe` boundaries must be re-validated — not "accept the
    // no-op." This applies to every `catch_unwind` site in this file.
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
    // OpenMLS may panic on AEAD decryption failure for tampered ciphertexts.
    // We guard against this with catch_unwind (same as in `decrypt`).
    // NOTE (ADR-057 §Prereq-4): inert under wasm `panic=abort`; browser build
    // must use `panic=unwind` (see the `decrypt` note above).
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
pub fn decrypt_with_sender_did(
    group: &mut ScpMlsGroup,
    ciphertext: &[u8],
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
    // NOTE (ADR-057 §Prereq-4): inert under wasm `panic=abort`; browser build
    // must use `panic=unwind` (see the `decrypt` note above).
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
    let sender_did = g
        .members()
        .find(|m| m.index == sender_leaf_index)
        .ok_or_else(|| {
            MlsError::DecryptionFailed(format!(
                "sender leaf index {sender_leaf_index:?} not found in group members"
            ))
        })
        .and_then(|m| {
            let basic_cred = BasicCredential::try_from(m.credential).map_err(|e| {
                MlsError::DecryptionFailed(format!("extracting BasicCredential: {e}"))
            })?;
            let scp_cred = crate::credential::ScpCredential::from_bytes(basic_cred.identity())
                .map_err(|e| MlsError::DecryptionFailed(format!("parsing ScpCredential: {e}")))?;
            Ok(scp_cred.did)
        })?;

    // Dispatch based on the processed message content type.
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(DecryptedContent::Application {
            plaintext: app_msg.into_bytes(),
            sender_did,
        }),
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
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
    use crate::group::{add_member, create_group, generate_key_package, join_group};

    #[allow(clippy::unwrap_used)]
    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_primitives::SigningKeyId::Active,
        )
        .unwrap()
    }

    /// Helper: set up Alice and Bob in a shared group.
    /// Returns (`alice_group`, `bob_group`).
    #[allow(clippy::unwrap_used)]
    fn setup_alice_bob() -> (ScpMlsGroup, ScpMlsGroup) {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();

        let add_result = add_member(&mut alice_group, bob_kp).unwrap();

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
        let mut charlie_group = create_group(&charlie_cred).unwrap();

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

        let content = decrypt_with_sender_did(&mut bob_group, &ct_bytes).unwrap();
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
        let mut alice_group = create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();

        let add_result = add_member(&mut alice_group, bob_kp).unwrap();
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
        let content = decrypt_with_sender_did(&mut bob_group, &commit_bytes).unwrap();
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
        let content = decrypt_with_sender_did(&mut bob_group, &ct_bytes).unwrap();
        assert!(
            matches!(&content, DecryptedContent::Application { .. }),
            "expected Application variant after Commit"
        );
        if let DecryptedContent::Application { plaintext: pt, .. } = content {
            assert_eq!(pt, plaintext, "must decrypt after Commit processing");
        }
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
