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

use openmls::prelude::*;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use super::error::MlsError;
use super::group::ScpMlsGroup;

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
    if group.destroyed {
        return Err(MlsError::GroupDestroyed);
    }

    group
        .group
        .create_message(&group.provider, &group.signer, plaintext)
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
    if group.destroyed {
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
    let processed = group
        .group
        .process_message(&group.provider, protocol_message)
        .map_err(|e| MlsError::DecryptionFailed(e.to_string()))?;

    // Extract the application message content.
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(app_msg.into_bytes()),
        _ => Err(MlsError::NotApplicationMessage),
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
    use crate::crypto::mls::credential::ScpCredential;
    use crate::crypto::mls::group::{add_member, create_group, generate_key_package, join_group};

    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(format!("did:dht:z6Mk{name}"), None)
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

        super::super::group::destroy_group(&mut alice_group).unwrap();

        let result = encrypt(&mut alice_group, b"should fail");
        assert!(result.is_err(), "encrypt must fail on destroyed group");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_on_destroyed_group_fails() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();

        let ciphertext_msg = encrypt(&mut alice_group, b"hello").unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        super::super::group::destroy_group(&mut bob_group).unwrap();

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
