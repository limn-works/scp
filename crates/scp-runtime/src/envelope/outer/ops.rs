//! Async MLS-dependent operations for outer envelopes.
//!
//! Contains the high-level send/receive path functions that depend on MLS
//! group state, sender key encryption, and `OpenMLS` types. Separated from the
//! pure sync types in `mod.rs` as a prerequisite for scp-protocol crate
//! extraction (#1446).

use sha2::{Digest, Sha256};

use super::{OuterEnvelope, create_outer_envelope};
use crate::envelope::inner::{InnerEnvelope, verify_inner_signature};
use scp_clock::Clock;
use scp_did::DID;
use scp_mls::encrypt::{DecryptedContent, decrypt_with_sender_did, encrypt, serialize_ciphertext};
use scp_mls::group::ScpMlsGroup;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::crypto::sender_keys::SenderKey;
use scp_protocol::crypto::sender_keys::encrypt::{decrypt_sender_layer, encrypt_sender_layer};
use scp_protocol::envelope::EnvelopeError;
use scp_protocol::envelope::padding::strip_padding;

// ---------------------------------------------------------------------------
// High-level send / receive path
// ---------------------------------------------------------------------------

/// Seals an inner envelope for transmission: serializes, encrypts with the
/// sender key layer, encrypts via MLS, and wraps in an outer envelope.
///
/// This is the primary **send-path** function. The caller is responsible for
/// constructing the [`InnerEnvelope`] (via [`create_inner_envelope`]) and
/// providing the routing metadata for the outer envelope.
///
/// # Processing order
///
/// 1. Serialize the inner envelope to `MessagePack`.
/// 2. Encrypt the serialized bytes with the sender's AES-256-GCM key
///    (per-sender forward secrecy layer — see ADR-007).
/// 3. Encrypt the sender-key ciphertext via MLS (`create_message` +
///    TLS-serialize).
/// 4. Wrap the MLS ciphertext in an [`OuterEnvelope`] with the provided
///    routing metadata.
///
/// # Arguments
///
/// * `inner` - The fully constructed inner envelope (already signed and
///   padded).
/// * `group` - The MLS group to encrypt within. Must be active.
/// * `sender_key` - The sender's current AES-256 sender key for this
///   context.
/// * `routing_id` - 32-byte per-context pseudonym for relay routing.
/// * `recipient_hint` - Optional 32-byte recipient pseudonym for directed
///   messages, or `None` for broadcast.
/// * `blob_ttl` - How long (seconds) the relay should store the envelope.
///
/// # Errors
///
/// Returns [`EnvelopeError::SerializationFailed`] if inner envelope
/// serialization fails.
/// Returns [`EnvelopeError::SenderKeyEncryptionFailed`] if sender key
/// AES-256-GCM encryption fails.
/// Returns [`EnvelopeError::MlsEncryptionFailed`] if MLS encryption fails.
/// Returns [`EnvelopeError::InvalidRoutingId`] if `routing_id` is not 32
/// bytes.
/// Returns [`EnvelopeError::InvalidRecipientHint`] if `recipient_hint` is
/// present but not 32 bytes.
///
/// See ADR-002 acceptance criterion 4 and ADR-007.
///
/// [`create_inner_envelope`]: crate::envelope::inner::sign::create_inner_envelope
pub fn seal_envelope(
    inner: &InnerEnvelope,
    group: &mut ScpMlsGroup,
    sender_key: &SenderKey,
    routing_id: &[u8],
    recipient_hint: Option<&[u8]>,
    blob_ttl: u32,
) -> Result<OuterEnvelope, EnvelopeError> {
    // 1. Serialize inner envelope to MessagePack.
    let serialized = rmp_serde::to_vec_named(inner)
        .map_err(|e| EnvelopeError::SerializationFailed(e.to_string()))?;

    // 2. Encrypt with sender key (AES-256-GCM), binding context metadata as AAD.
    let sender_encrypted = encrypt_sender_layer(
        sender_key,
        &serialized,
        &inner.context_id,
        &inner.sender_did,
        inner.epoch,
        inner.sequence,
    )
    .map_err(|e| EnvelopeError::SenderKeyEncryptionFailed(e.to_string()))?;

    // 3. Encrypt via MLS.
    let mls_message = encrypt(group, &sender_encrypted)
        .map_err(|e| EnvelopeError::MlsEncryptionFailed(e.to_string()))?;

    let encrypted_blob = serialize_ciphertext(&mls_message)
        .map_err(|e| EnvelopeError::MlsEncryptionFailed(e.to_string()))?;

    // 4. Wrap in outer envelope.
    create_outer_envelope(routing_id, recipient_hint, blob_ttl, encrypted_blob)
}

/// The sender-layer AAD fields a receiver expects on an envelope (ADR-007).
///
/// The fields are the context, the sender DID, the sender-key epoch, and the
/// sequence number. [`open_envelope`] authenticates them through the
/// sender-layer AEAD and also requires `sender_did` to equal both the MLS sender's
/// credential DID and the inner envelope's `sender_did` (09 §9.8.1).
#[derive(Debug, Clone, Copy)]
pub struct SenderLayerAad<'a> {
    /// The context the envelope belongs to.
    pub context_id: &'a str,
    /// The DID the receiver expects sent the envelope.
    pub sender_did: &'a str,
    /// The sender-key epoch.
    pub epoch: u64,
    /// The sender's per-epoch sequence number.
    pub sequence: u64,
}

/// Opens and verifies a received outer envelope.
///
/// It decrypts via MLS, binds the sender identities, decrypts with the sender
/// key, deserializes, strips padding, verifies content integrity, and verifies
/// the inner signature.
///
/// This is the primary **receive-path** function with full integrity
/// verification. It rejects messages that fail any verification step.
///
/// The sender's identity comes from the inner-envelope signature, checked
/// against the key `key_resolver` resolves for `(inner.sender_did,
/// inner.signing_key_id)` — never from the MLS leaf signature key, which is a
/// P-256 MLS key distinct from the DID's signing keys (09 §9.8.1; 09:856).
/// Because every member holds every other member's sender key, the DID in
/// the MLS sender's credential, the inner `sender_did`, and the caller's
/// `aad.sender_did` must all be equal; otherwise a member could re-send another
/// member's signed inner envelope from its own leaf.
///
/// # Processing order
///
/// 1. Decrypt the `encrypted_blob` via MLS and read the sender DID from the
///    MLS sender's credential (membership tag verification and
///    generation-number replay prevention are enforced by the MLS layer). A
///    Commit or Proposal is not an envelope and is rejected; a Commit has
///    already been merged into `group` by then, as on the production receive
///    path.
/// 2. Require the MLS sender DID to equal `aad.sender_did`.
/// 3. Decrypt the MLS plaintext with the sender's AES-256-GCM key
///    (per-sender forward secrecy layer — see ADR-007); the AAD binds
///    `aad.sender_did`.
/// 4. Deserialize the sender-key-decrypted bytes into an [`InnerEnvelope`]
///    and require its `sender_did` to equal `aad.sender_did`.
/// 5. Strip bucket padding from the payload to recover the original
///    plaintext.
/// 6. Verify `payload_hash == SHA-256(stripped_payload)` — reject on content
///    integrity failure.
/// 7. Resolve the verification key for `(inner.sender_did,
///    inner.signing_key_id)` (`#active` or `#agent`).
/// 8. Verify the inner Ed25519 signature against it — reject on mismatch.
/// 9. Return the verified inner envelope.
///
/// # Arguments
///
/// * `outer` - The received outer envelope.
/// * `group` - The MLS group to decrypt within. Must be active.
/// * `sender_key` - The sender's current AES-256 sender key for this
///   context.
/// * `aad` - The sender-layer AAD fields; its `sender_did` is also the
///   sender the caller expects.
/// * `key_resolver` - Resolves a DID's `#active` or `#agent` verification
///   key.
/// * `clock` - The injected clock `decrypt_with_sender_did` validates a
///   Commit's `KeyPackage` lifetimes against.
///
/// # Errors
///
/// Returns [`EnvelopeError::MlsDecryptionFailed`] if MLS decryption fails
/// (including replay rejection via generation number) or the message is a
/// Commit or Proposal rather than an application message.
/// Returns [`EnvelopeError::SenderMismatch`] if the MLS sender DID or the
/// inner `sender_did` differs from `aad.sender_did`.
/// Returns [`EnvelopeError::SenderKeyDecryptionFailed`] if sender key
/// AES-256-GCM decryption fails (wrong key, tampered, or corrupted).
/// Returns [`EnvelopeError::DeserializationFailed`] if the decrypted bytes
/// are not a valid inner envelope.
/// Returns [`EnvelopeError::InvalidPadding`] if padding cannot be stripped.
/// Returns [`EnvelopeError::ContentIntegrityFailed`] if `payload_hash` does
/// not match `SHA-256(stripped_payload)`.
/// Returns [`EnvelopeError::VerificationFailed`] if no key resolves for the
/// inner sender and signing key id, or the key or signature bytes are
/// malformed.
/// Returns [`EnvelopeError::InnerSignatureMismatch`] if the signature is
/// well-formed but does not match.
///
/// See ADR-002 acceptance criterion 5, ADR-007, and 09 §9.8.1.
pub fn open_envelope(
    outer: &OuterEnvelope,
    group: &mut ScpMlsGroup,
    sender_key: &SenderKey,
    aad: &SenderLayerAad<'_>,
    key_resolver: &KeyResolver,
    clock: &dyn Clock,
) -> Result<InnerEnvelope, EnvelopeError> {
    // 1. MLS decrypt; the sender DID comes from the MLS sender's credential.
    let (mls_plaintext, mls_sender) =
        match decrypt_with_sender_did(group, &outer.encrypted_blob, clock)
            .map_err(|e| EnvelopeError::MlsDecryptionFailed(e.to_string()))?
        {
            DecryptedContent::Application {
                plaintext,
                sender_did,
            } => (plaintext, sender_did),
            DecryptedContent::Commit { .. } | DecryptedContent::Proposal { .. } => {
                return Err(EnvelopeError::MlsDecryptionFailed(
                    "not an application message".to_owned(),
                ));
            }
        };

    // 2. The MLS sender must be the sender the caller expects (09 §9.8.1).
    if mls_sender != aad.sender_did {
        return Err(EnvelopeError::SenderMismatch {
            mls_sender,
            inner_sender: String::new(),
            caller_sender: aad.sender_did.to_owned(),
        });
    }

    // 3. Decrypt sender key layer (AES-256-GCM), verifying AAD binding.
    let plaintext = decrypt_sender_layer(
        sender_key,
        &mls_plaintext,
        aad.context_id,
        aad.sender_did,
        aad.epoch,
        aad.sequence,
    )
    .map_err(|e| EnvelopeError::SenderKeyDecryptionFailed(e.to_string()))?;

    // 4. Deserialize inner envelope via `from_bytes` (#347, #863).
    //    `from_bytes` applies a pre-deserialization size check against
    //    `MAX_ENVELOPE_SIZE` before invoking the deserializer, preventing
    //    `serde`'s `#[serde(flatten)]` buffering from allocating memory for
    //    oversized inputs. The outer envelope's `BOUNDED_BYTES_MAX` limit on
    //    `encrypted_blob` bounds the decrypted size transitively;
    //    `from_bytes` acts as defense in depth.
    let inner = InnerEnvelope::from_bytes(&plaintext)?;

    // 4a. Version compatibility is checked inside `verify_inner_signature`
    //     (step 8 below), which rejects incompatible major versions and warns
    //     on minor mismatches. No duplicate check here — standalone callers of
    //     `verify_inner_signature` still get the check.

    // 4b. The inner sender must be the sender the caller expects, which step 2
    //     already bound to the MLS sender (09 §9.8.1).
    if inner.sender_did != aad.sender_did {
        return Err(EnvelopeError::SenderMismatch {
            mls_sender,
            inner_sender: inner.sender_did,
            caller_sender: aad.sender_did.to_owned(),
        });
    }

    // 5. Strip padding to recover original payload.
    let stripped_payload = strip_padding(&inner.payload)?;

    // 6. Verify content integrity: payload_hash == SHA-256(stripped_payload).
    //    Constant-time comparison to prevent timing side-channels.
    let computed_hash = Sha256::digest(&stripped_payload);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        computed_hash.as_slice(),
        &inner.payload_hash[..],
    )) {
        return Err(EnvelopeError::ContentIntegrityFailed);
    }

    // 7. Resolve the key the inner envelope declares it was signed with
    //    (`#active` or `#agent`) for the bound sender DID.
    let verifying_key = key_resolver(&DID(inner.sender_did.clone()), inner.signing_key_id)
        .ok_or_else(|| {
            EnvelopeError::VerificationFailed(format!(
                "no key for {}{}",
                inner.sender_did, inner.signing_key_id
            ))
        })?;

    // 8. Verify the inner signature against the resolved key.
    let valid = verify_inner_signature(&inner, verifying_key.as_bytes())?;
    if !valid {
        return Err(EnvelopeError::InnerSignatureMismatch);
    }

    // 9. Return the verified inner envelope.
    Ok(inner)
}

/// Integration tests for the high-level seal/open envelope operations.
///
/// These tests exercise the full send -> receive pipeline including MLS
/// encryption/decryption, inner envelope serialization, padding, content
/// integrity verification, and signature verification.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod seal_open_tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use openmls::prelude::*;
    use scp_clock::SystemClock;
    use scp_platform::testing::InMemoryKeyCustody;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::envelope::inner::sign::create_inner_envelope;
    use crate::envelope::inner::{InnerEnvelopeParams, MessageType, Provenance};
    use scp_did::SigningKeyId;
    use scp_mls::credential::ScpCredential;
    use scp_mls::group::{add_member, create_group, generate_key_package, join_group};
    use scp_protocol::crypto::sender_keys::generate_sender_key;
    use scp_protocol::envelope::padding::strip_padding;

    /// One group member: the DID in its MLS credential and its view of the
    /// group. Its identity keys are separate from its P-256 MLS leaf key
    /// (09 §9.8.1).
    struct Member {
        did: String,
        group: ScpMlsGroup,
    }

    fn did_of(name: &str) -> String {
        format!("did:dht:z6Mk{name}")
    }

    fn credential(name: &str) -> ScpCredential {
        ScpCredential::new(did_of(name), None, SigningKeyId::Active).unwrap()
    }

    /// The fixed Ed25519 seed of `did`'s `key_id` identity key.
    fn identity_seed(did: &str, key_id: SigningKeyId) -> [u8; 32] {
        Sha256::new()
            .chain_update(b"ops-test-identity")
            .chain_update(did.as_bytes())
            .chain_update(key_id.to_string().as_bytes())
            .finalize()
            .into()
    }

    fn verifying_key(did: &str, key_id: SigningKeyId) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::SigningKey::from_bytes(&identity_seed(did, key_id)).verifying_key()
    }

    /// A resolver that resolves exactly `entries` and nothing else.
    fn resolver(entries: Vec<(String, SigningKeyId, ed25519_dalek::VerifyingKey)>) -> KeyResolver {
        let map: HashMap<(String, SigningKeyId), ed25519_dalek::VerifyingKey> = entries
            .into_iter()
            .map(|(did, key_id, key)| ((did, key_id), key))
            .collect();
        Arc::new(move |did: &DID, key_id: SigningKeyId| map.get(&(did.0.clone(), key_id)).copied())
    }

    /// A resolver holding each DID's `#active` identity key.
    fn active_resolver(dids: &[&str]) -> KeyResolver {
        resolver(
            dids.iter()
                .map(|did| {
                    (
                        (*did).to_owned(),
                        SigningKeyId::Active,
                        verifying_key(did, SigningKeyId::Active),
                    )
                })
                .collect(),
        )
    }

    /// The first name creates the group and adds each later name in order;
    /// every earlier joiner processes each later Add commit. Returns the
    /// members in `names` order, all at the same epoch.
    fn setup_group(names: &[&str]) -> Vec<Member> {
        let mut members = vec![Member {
            did: did_of(names[0]),
            group: create_group(
                &credential(names[0]),
                &scp_crypto::p256::testing::uncompressed_point_for(&(credential(names[0])).did),
                &SystemClock,
            )
            .unwrap(),
        }];
        for name in &names[1..] {
            let (bundle, signer, provider) = generate_key_package(
                &credential(name),
                &scp_crypto::p256::testing::uncompressed_point_for(&(credential(name)).did),
                &SystemClock,
            )
            .unwrap();
            let key_package: KeyPackageIn = bundle.key_package().clone().into();
            let added = add_member(&mut members[0].group, key_package, &SystemClock).unwrap();
            let commit = serialize_ciphertext(&added.commit).unwrap();
            for member in members.iter_mut().skip(1) {
                let processed =
                    decrypt_with_sender_did(&mut member.group, &commit, &SystemClock).unwrap();
                assert!(matches!(processed, DecryptedContent::Commit { .. }));
            }
            let group = join_group(&added.welcome, provider, signer).unwrap();
            members.push(Member {
                did: did_of(name),
                group,
            });
        }
        members
    }

    /// Alice and Bob in one group.
    fn alice_and_bob() -> (Member, Member) {
        let mut members = setup_group(&["alice", "bob"]);
        let bob = members.pop().unwrap();
        let alice = members.pop().unwrap();
        (alice, bob)
    }

    /// An inner envelope from `sender_did`, signed with its `key_id` identity
    /// key and declaring that key id.
    async fn sign_inner_as(
        sender_did: &str,
        key_id: SigningKeyId,
        payload: &[u8],
        provenance: Option<Provenance>,
    ) -> InnerEnvelope {
        let custody = InMemoryKeyCustody::new();
        let signing_key = custody
            .import_ed25519_key(&identity_seed(sender_did, key_id))
            .await;
        create_inner_envelope(
            &InnerEnvelopeParams {
                version: crate::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did,
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload,
                provenance,
                signing_key_id: key_id,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap()
    }

    /// An inner envelope from `sender`, signed with its `#active` key.
    async fn create_test_inner(
        sender: &Member,
        payload: &[u8],
        provenance: Option<Provenance>,
    ) -> InnerEnvelope {
        sign_inner_as(&sender.did, SigningKeyId::Active, payload, provenance).await
    }

    /// The AAD fields an honest receiver expects for `inner`.
    fn aad(inner: &InnerEnvelope) -> SenderLayerAad<'_> {
        SenderLayerAad {
            context_id: &inner.context_id,
            sender_did: &inner.sender_did,
            epoch: inner.epoch,
            sequence: inner.sequence,
        }
    }

    fn seal(inner: &InnerEnvelope, sender: &mut Member, sender_key: &SenderKey) -> OuterEnvelope {
        seal_envelope(
            inner,
            &mut sender.group,
            sender_key,
            &[0xAA; 32],
            None,
            3600,
        )
        .unwrap()
    }

    fn open_as(
        outer: &OuterEnvelope,
        receiver: &mut Member,
        sender_key: &SenderKey,
        aad: &SenderLayerAad<'_>,
        key_resolver: &KeyResolver,
    ) -> Result<InnerEnvelope, EnvelopeError> {
        open_envelope(
            outer,
            &mut receiver.group,
            sender_key,
            aad,
            key_resolver,
            &SystemClock,
        )
    }

    // -----------------------------------------------------------------------
    // seal_envelope tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn seal_envelope_produces_valid_outer_envelope() {
        let (mut alice, _bob) = alice_and_bob();
        let inner = create_test_inner(&alice, b"hello world", None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice.group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();

        assert_eq!(outer.routing_id, routing_id);
        assert!(outer.recipient_hint.is_none());
        assert_eq!(outer.blob_ttl, 3600);
        assert!(
            !outer.encrypted_blob.is_empty(),
            "encrypted_blob must not be empty"
        );
    }

    #[tokio::test]
    async fn seal_envelope_with_recipient_hint() {
        let (mut alice, _bob) = alice_and_bob();
        let inner = create_test_inner(&alice, b"directed message", None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];
        let recipient = [0xBB; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice.group,
            &sender_key,
            &routing_id,
            Some(&recipient),
            7200,
        )
        .unwrap();

        assert_eq!(outer.recipient_hint.as_deref(), Some(recipient.as_slice()));
        assert_eq!(outer.blob_ttl, 7200);
    }

    #[tokio::test]
    async fn seal_envelope_rejects_invalid_routing_id() {
        let (mut alice, _bob) = alice_and_bob();
        let inner = create_test_inner(&alice, b"test", None).await;
        let sender_key = generate_sender_key();

        let result = seal_envelope(
            &inner,
            &mut alice.group,
            &sender_key,
            &[0xAA; 16],
            None,
            3600,
        );
        assert!(result.is_err(), "should reject 16-byte routing_id");
    }

    // -----------------------------------------------------------------------
    // open_envelope tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn seal_then_open_roundtrip_produces_original_content() {
        let (mut alice, mut bob) = alice_and_bob();
        let original_payload = b"hello, sealed world!";
        let inner = create_test_inner(&alice, original_payload, None).await;
        let sender_key = generate_sender_key();
        let outer = seal(&inner, &mut alice, &sender_key);

        // Bob verifies against Alice's resolved `#active` identity key
        // (09 §9.8.1; 09:856).
        let recovered = open_as(
            &outer,
            &mut bob,
            &sender_key,
            &aad(&inner),
            &active_resolver(&[&alice.did]),
        )
        .unwrap();

        assert_eq!(recovered.context_id, inner.context_id);
        assert_eq!(recovered.sender_did, inner.sender_did);
        assert_eq!(recovered.epoch, inner.epoch);
        assert_eq!(recovered.generation, inner.generation);
        assert_eq!(recovered.sequence, inner.sequence);
        assert_eq!(recovered.timestamp, inner.timestamp);
        assert_eq!(recovered.payload_hash, inner.payload_hash);
        assert_eq!(recovered.payload, inner.payload);
        assert_eq!(recovered.signature, inner.signature);

        let stripped = strip_padding(&recovered.payload).unwrap();
        assert_eq!(stripped, original_payload);
    }

    #[tokio::test]
    async fn seal_then_open_roundtrip_with_provenance() {
        let (mut alice, mut bob) = alice_and_bob();
        let provenance = Provenance {
            source: "test-outlet".into(),
            upstream_hash: Some("abc123".into()),
        };
        let inner =
            create_test_inner(&alice, b"payload with provenance", Some(provenance.clone())).await;
        let sender_key = generate_sender_key();
        let outer = seal(&inner, &mut alice, &sender_key);

        let recovered = open_as(
            &outer,
            &mut bob,
            &sender_key,
            &aad(&inner),
            &active_resolver(&[&alice.did]),
        )
        .unwrap();

        assert_eq!(recovered.provenance, Some(provenance));
        assert_eq!(recovered.provenance_hash, inner.provenance_hash);
    }

    #[tokio::test]
    async fn open_envelope_rejects_tampered_encrypted_blob() {
        let (mut alice, mut bob) = alice_and_bob();
        let inner = create_test_inner(&alice, b"test", None).await;
        let sender_key = generate_sender_key();
        let mut outer = seal(&inner, &mut alice, &sender_key);

        // Tamper with the encrypted blob (corrupt AEAD tag).
        if let Some(byte) = outer.encrypted_blob.last_mut() {
            *byte ^= 0xFF;
        }

        // OpenMLS can panic on AEAD decryption failure; the
        // catch_unwind guard converts the panic to an error.
        let result = open_as(
            &outer,
            &mut bob,
            &sender_key,
            &aad(&inner),
            &active_resolver(&[&alice.did]),
        );
        assert!(
            matches!(result, Err(EnvelopeError::MlsDecryptionFailed(_))),
            "error should be MlsDecryptionFailed, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn open_envelope_rejects_mismatched_payload_hash() {
        let (mut alice, mut bob) = alice_and_bob();
        let mut inner = create_test_inner(&alice, b"original data", None).await;

        // Tamper with payload_hash (this also breaks the signature, but the
        // content integrity check runs first).
        inner.payload_hash = [0xFF; 32];

        let sender_key = generate_sender_key();
        let outer = seal(&inner, &mut alice, &sender_key);

        let result = open_as(
            &outer,
            &mut bob,
            &sender_key,
            &aad(&inner),
            &active_resolver(&[&alice.did]),
        );
        assert!(
            matches!(result, Err(EnvelopeError::ContentIntegrityFailed)),
            "error should be ContentIntegrityFailed, got: {result:?}"
        );
    }

    /// 09 §9.8.1: an inner envelope whose signature does not verify under the
    /// key resolved for its sender is rejected. Here the resolver returns a
    /// key other than the one Alice signed with.
    #[tokio::test]
    async fn open_envelope_rejects_wrong_signing_key() {
        let (mut alice, mut bob) = alice_and_bob();
        let inner = create_test_inner(&alice, b"signed by alice", None).await;
        let sender_key = generate_sender_key();
        let outer = seal(&inner, &mut alice, &sender_key);

        let wrong_key = resolver(vec![(
            alice.did.clone(),
            SigningKeyId::Active,
            verifying_key("did:dht:z6MkSomeoneElse", SigningKeyId::Active),
        )]);
        let result = open_as(&outer, &mut bob, &sender_key, &aad(&inner), &wrong_key);
        assert!(
            matches!(result, Err(EnvelopeError::InnerSignatureMismatch)),
            "error should be InnerSignatureMismatch, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn open_envelope_rejects_replayed_message() {
        let (mut alice, mut bob) = alice_and_bob();
        let inner = create_test_inner(&alice, b"replay me", None).await;
        let sender_key = generate_sender_key();
        let outer = seal(&inner, &mut alice, &sender_key);
        let keys = active_resolver(&[&alice.did]);

        // First open succeeds.
        let _recovered = open_as(&outer, &mut bob, &sender_key, &aad(&inner), &keys).unwrap();

        // Second open with same ciphertext should fail (MLS generation
        // number replay prevention).
        let replay_result = open_as(&outer, &mut bob, &sender_key, &aad(&inner), &keys);
        assert!(
            replay_result.is_err(),
            "open_envelope must reject replayed ciphertext"
        );
    }

    #[tokio::test]
    async fn open_envelope_rejects_garbage_encrypted_blob() {
        let (_alice, mut bob) = alice_and_bob();
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let outer =
            create_outer_envelope(&routing_id, None, 3600, vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

        // AAD values are irrelevant: MLS decrypt fails on garbage before
        // the sender key layer is reached.
        let result = open_as(
            &outer,
            &mut bob,
            &sender_key,
            &SenderLayerAad {
                context_id: "ctx-1",
                sender_did: "did:dht:z6MkDummy",
                epoch: 0,
                sequence: 0,
            },
            &active_resolver(&[]),
        );
        assert!(
            matches!(result, Err(EnvelopeError::MlsDecryptionFailed(_))),
            "open_envelope must reject garbage encrypted_blob, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn seal_then_open_empty_payload_roundtrip() {
        let (mut alice, mut bob) = alice_and_bob();
        let inner = create_test_inner(&alice, b"", None).await;
        let sender_key = generate_sender_key();
        let outer = seal(&inner, &mut alice, &sender_key);

        let recovered = open_as(
            &outer,
            &mut bob,
            &sender_key,
            &aad(&inner),
            &active_resolver(&[&alice.did]),
        )
        .unwrap();

        let stripped = strip_padding(&recovered.payload).unwrap();
        assert!(stripped.is_empty(), "empty payload should roundtrip");

        // Verify payload_hash matches SHA-256 of empty bytes.
        let expected_hash: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(recovered.payload_hash, expected_hash);
    }

    #[tokio::test]
    async fn seal_then_open_multiple_messages() {
        let (mut alice, mut bob) = alice_and_bob();
        let sender_key = generate_sender_key();
        let keys = active_resolver(&[&alice.did]);

        let messages: &[&[u8]] = &[b"first", b"second", b"third"];

        // Seal all messages, keeping the inner envelopes for open_envelope AAD.
        let mut outers = Vec::new();
        let mut inners = Vec::new();
        for msg in messages {
            let inner = create_test_inner(&alice, msg, None).await;
            outers.push(seal(&inner, &mut alice, &sender_key));
            inners.push(inner);
        }

        // Open all messages in order.
        for (i, outer) in outers.iter().enumerate() {
            let recovered = open_as(outer, &mut bob, &sender_key, &aad(&inners[i]), &keys).unwrap();
            let stripped = strip_padding(&recovered.payload).unwrap();
            assert_eq!(
                stripped, messages[i],
                "message {i} must roundtrip correctly"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Sender binding and key resolution (09 §9.8.1; 09:856)
    // -----------------------------------------------------------------------

    /// An envelope whose inner and expected sender is a DID other than the
    /// MLS sender's credential DID is rejected with `SenderMismatch`, even
    /// though the resolver holds a key that verifies its signature.
    #[tokio::test]
    async fn open_envelope_rejects_sender_other_than_mls_sender() {
        let (mut alice, mut bob) = alice_and_bob();
        let nobody = did_of("NOBODY");
        let inner = sign_inner_as(&nobody, SigningKeyId::Active, b"from nobody", None).await;
        let sender_key = generate_sender_key();
        let outer = seal(&inner, &mut alice, &sender_key);

        let result = open_as(
            &outer,
            &mut bob,
            &sender_key,
            &aad(&inner),
            &active_resolver(&[&alice.did, &nobody]),
        );
        match result {
            Err(EnvelopeError::SenderMismatch {
                mls_sender,
                caller_sender,
                ..
            }) => {
                assert_eq!(mls_sender, alice.did);
                assert_eq!(caller_sender, nobody);
            }
            other => panic!("expected SenderMismatch, got {other:?}"),
        }
    }

    /// T10: an envelope signed with Alice's `#agent` key verifies when the
    /// resolver resolves `(alice, #agent)`, and fails closed with
    /// `VerificationFailed` when the resolver holds only Alice's `#active`
    /// key. A receiver that always resolved `#active` rejects every
    /// agent-signed envelope.
    #[tokio::test]
    async fn open_envelope_verifies_agent_signed_envelope_against_agent_key() {
        let (mut alice, mut bob) = alice_and_bob();
        let inner = sign_inner_as(&alice.did, SigningKeyId::Agent, b"agent says", None).await;
        let sender_key = generate_sender_key();
        let first = seal(&inner, &mut alice, &sender_key);
        let second = seal(&inner, &mut alice, &sender_key);

        let active_only = active_resolver(&[&alice.did]);
        match open_as(&first, &mut bob, &sender_key, &aad(&inner), &active_only) {
            Err(EnvelopeError::VerificationFailed(msg)) => {
                assert!(msg.contains("#agent"), "{msg}");
                assert!(msg.contains(&alice.did), "{msg}");
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }

        let agent = resolver(vec![(
            alice.did.clone(),
            SigningKeyId::Agent,
            verifying_key(&alice.did, SigningKeyId::Agent),
        )]);
        let recovered = open_as(&second, &mut bob, &sender_key, &aad(&inner), &agent).unwrap();
        assert_eq!(recovered.signing_key_id, SigningKeyId::Agent);
        assert_eq!(recovered.sender_did, alice.did);
    }

    /// Alice, Bob and Mallory in one group, Alice's sender key (which every
    /// member holds), and an inner envelope Alice signed.
    async fn replay_fixture() -> (Member, Member, Member, SenderKey, InnerEnvelope) {
        let mut members = setup_group(&["alice", "bob", "mallory"]);
        let mallory = members.pop().unwrap();
        let bob = members.pop().unwrap();
        let alice = members.pop().unwrap();
        let alice_sender_key = generate_sender_key();
        let inner = create_test_inner(&alice, b"alice's words", None).await;
        (alice, bob, mallory, alice_sender_key, inner)
    }

    /// T11(i): Mallory re-sends Alice's signed inner envelope from Mallory's
    /// own MLS leaf, sealed with Alice's sender key under Alice's AAD. Bob,
    /// expecting Alice, rejects it because the MLS sender is Mallory. The
    /// honest control shows the same inner envelope opens when Alice sends it.
    #[tokio::test]
    async fn open_envelope_rejects_replay_under_other_members_leaf() {
        let (mut alice, mut bob, mut mallory, alice_sk, inner) = replay_fixture().await;
        let keys = active_resolver(&[&alice.did, &mallory.did]);

        let honest = seal(&inner, &mut alice, &alice_sk);
        open_as(&honest, &mut bob, &alice_sk, &aad(&inner), &keys).unwrap();

        let replayed = seal(&inner, &mut mallory, &alice_sk);
        match open_as(&replayed, &mut bob, &alice_sk, &aad(&inner), &keys) {
            Err(EnvelopeError::SenderMismatch {
                mls_sender,
                caller_sender,
                ..
            }) => {
                assert_eq!(mls_sender, mallory.did);
                assert_eq!(caller_sender, alice.did);
            }
            other => panic!("expected SenderMismatch, got {other:?}"),
        }
    }

    /// T11(ii): Mallory re-sends Alice's signed inner envelope from Mallory's
    /// own leaf under Mallory's own sender key and AAD. The MLS sender and
    /// the expected sender agree (Mallory), but the inner sender is Alice, so
    /// Bob rejects it; without that check the resolver would return Alice's
    /// key and the signature would verify.
    #[tokio::test]
    async fn open_envelope_rejects_inner_sender_other_than_caller_sender() {
        let (alice, mut bob, mut mallory, _alice_sk, inner) = replay_fixture().await;
        let keys = active_resolver(&[&alice.did, &mallory.did]);
        let mallory_sk = generate_sender_key();

        let serialized = rmp_serde::to_vec_named(&inner).unwrap();
        let sender_layer = encrypt_sender_layer(
            &mallory_sk,
            &serialized,
            &inner.context_id,
            &mallory.did,
            inner.epoch,
            inner.sequence,
        )
        .unwrap();
        let mls_message = encrypt(&mut mallory.group, &sender_layer).unwrap();
        let ciphertext = serialize_ciphertext(&mls_message).unwrap();
        let outer = create_outer_envelope(&[0xAA; 32], None, 3600, ciphertext).unwrap();

        let expected = SenderLayerAad {
            context_id: &inner.context_id,
            sender_did: &mallory.did,
            epoch: inner.epoch,
            sequence: inner.sequence,
        };
        match open_as(&outer, &mut bob, &mallory_sk, &expected, &keys) {
            Err(EnvelopeError::SenderMismatch {
                mls_sender,
                inner_sender,
                caller_sender,
            }) => {
                assert_eq!(mls_sender, mallory.did);
                assert_eq!(inner_sender, alice.did);
                assert_eq!(caller_sender, mallory.did);
            }
            other => panic!("expected SenderMismatch, got {other:?}"),
        }
    }

    /// T12: a Commit handed to `open_envelope` is not an envelope and is
    /// rejected with `MlsDecryptionFailed`; the commit has been merged by
    /// then, as on the production receive path.
    #[tokio::test]
    async fn open_envelope_rejects_commit_input() {
        let (mut alice, mut bob) = alice_and_bob();
        let (bundle, _signer, _provider) = generate_key_package(
            &credential("carol"),
            &scp_crypto::p256::testing::uncompressed_point_for(&(credential("carol")).did),
            &SystemClock,
        )
        .unwrap();
        let added = add_member(
            &mut alice.group,
            bundle.key_package().clone().into(),
            &SystemClock,
        )
        .unwrap();
        let commit = serialize_ciphertext(&added.commit).unwrap();
        let outer = create_outer_envelope(&[0xAA; 32], None, 3600, commit).unwrap();
        let epoch_before = bob.group.epoch().unwrap();

        let result = open_as(
            &outer,
            &mut bob,
            &generate_sender_key(),
            &SenderLayerAad {
                context_id: "ctx-1",
                sender_did: &alice.did,
                epoch: 1,
                sequence: 1,
            },
            &active_resolver(&[&alice.did]),
        );
        match result {
            Err(EnvelopeError::MlsDecryptionFailed(msg)) => {
                assert_eq!(msg, "not an application message");
            }
            other => panic!("expected MlsDecryptionFailed, got {other:?}"),
        }
        assert_eq!(bob.group.epoch().unwrap(), epoch_before + 1);
    }

    // -----------------------------------------------------------------------
    // sender key layer tests
    // -----------------------------------------------------------------------

    /// Confirms that ciphertext produced by `seal_envelope` cannot be opened
    /// without the correct sender key, even if MLS decryption succeeds.
    /// Using the wrong sender key must yield `SenderKeyDecryptionFailed`.
    #[tokio::test]
    async fn open_envelope_rejects_wrong_sender_key() {
        let (mut alice, mut bob) = alice_and_bob();
        let inner = create_test_inner(&alice, b"sender key protected", None).await;
        let correct_sender_key = generate_sender_key();
        let wrong_sender_key = generate_sender_key();
        let outer = seal(&inner, &mut alice, &correct_sender_key);

        // Open with a different sender key — MLS decryption succeeds, but
        // sender key decryption must fail.
        let result = open_as(
            &outer,
            &mut bob,
            &wrong_sender_key,
            &aad(&inner),
            &active_resolver(&[&alice.did]),
        );
        assert!(
            matches!(result, Err(EnvelopeError::SenderKeyDecryptionFailed(_))),
            "error should be SenderKeyDecryptionFailed, got: {result:?}"
        );
    }

    /// Confirms that tampered sender-key ciphertext is rejected with an
    /// authentication failure before inner envelope deserialization is
    /// attempted. We manually build the pipeline to inject tampering at
    /// the sender-key-ciphertext layer (after sender key encrypt, before
    /// MLS encrypt).
    #[tokio::test]
    async fn open_envelope_rejects_tampered_sender_key_ciphertext() {
        let (mut alice, mut bob) = alice_and_bob();
        let inner = create_test_inner(&alice, b"tamper target", None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        // Step 1: Serialize inner envelope.
        let serialized = rmp_serde::to_vec_named(&inner).unwrap();

        // Step 2: Encrypt with sender key.
        let mut sender_encrypted = encrypt_sender_layer(
            &sender_key,
            &serialized,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        )
        .unwrap();

        // Step 3: Tamper with the sender-key ciphertext (flip a byte in
        // the encrypted portion, after the 12-byte nonce).
        let tamper_index = 12 + 1;
        sender_encrypted[tamper_index] ^= 0xFF;

        // Step 4: MLS-encrypt the tampered bytes (MLS doesn't know they're
        // tampered — it just encrypts whatever it receives).
        let mls_message = encrypt(&mut alice.group, &sender_encrypted).unwrap();
        let encrypted_blob = serialize_ciphertext(&mls_message).unwrap();

        // Step 5: Wrap in outer envelope.
        let outer = create_outer_envelope(&routing_id, None, 3600, encrypted_blob).unwrap();

        // Step 6: Try to open — MLS decryption succeeds, but sender key
        // authentication tag verification must fail.
        let result = open_as(
            &outer,
            &mut bob,
            &sender_key,
            &aad(&inner),
            &active_resolver(&[&alice.did]),
        );
        let err_msg = format!("{result:?}");
        assert!(
            matches!(result, Err(EnvelopeError::SenderKeyDecryptionFailed(_))),
            "error should be SenderKeyDecryptionFailed (auth tag failure), got: {err_msg}"
        );
        assert!(
            err_msg.contains("authentication tag verification failed"),
            "error should mention authentication tag failure, got: {err_msg}"
        );
    }

    mod proptest_seal_open {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(10))]
            #[test]
            fn seal_open_roundtrip_arbitrary(
                payload in proptest::collection::vec(any::<u8>(), 0..4000)
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let (mut alice, mut bob) = alice_and_bob();
                    let inner = create_test_inner(&alice, &payload, None).await;
                    let sender_key = generate_sender_key();
                    let outer = seal(&inner, &mut alice, &sender_key);

                    let recovered = open_as(
                        &outer,
                        &mut bob,
                        &sender_key,
                        &aad(&inner),
                        &active_resolver(&[&alice.did]),
                    ).unwrap();

                    let stripped = strip_padding(&recovered.payload).unwrap();
                    prop_assert_eq!(stripped, payload);

                    Ok(())
                })?;
            }
        }
    }
}
