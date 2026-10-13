//! The push signature verifier seam (§10.7.1 step 3).
//!
//! A relay that offers push verifies each `PushRegistration` and
//! `PushDeregistration` (`22-human-readable-addressing.md` §22.11.4) against
//! the key the registrant's key state lists `Current` in the `#active` role,
//! resolved by replaying the registrant's key-event log
//! (`09-security-model.md` §9.7.4.2 R2, R3, R8). The relay receives the
//! verifier by injection as `Arc<dyn PushSignatureVerifier>` (ADR-062,
//! capability injection) and never reaches it through a global.
//!
//! A verifier takes the typed message and the relay's own canonical URL, and
//! computes the signature preimage only through
//! [`push_registration_signing_bytes`] and
//! [`push_deregistration_signing_bytes`], the two functions that own the
//! §9.5.2 push preimages. It never takes raw signed bytes, so no caller can
//! hand it a preimage that differs from the message it stores.
//!
//! Two implementations exist:
//!
//! - [`KelPushVerifier`], the production verifier. The keri workstream builds
//!   its body after SCP-308 S1 and the §9.7.4.2 R2, R3 and R8 key-state
//!   resolution land. Until then it refuses every message with
//!   [`PushVerifyError::VerifierUnavailable`], so a push-enabled relay answers
//!   `5003` and accepts nothing unverified.
//! - `TestPushVerifier`, compiled only under `cfg(test)` or the `testing`
//!   feature, which checks a real P-256 signature against a key the test
//!   supplies.
//!
//! No verifier that returns `Ok` without checking a signature exists in any
//! build, `testing` included.

use std::fmt::Debug;

use scp_did::DID;
use scp_protocol::discovery::push::{
    PushDeregistration, PushMessageError, PushRegistration, push_deregistration_signing_bytes,
    push_registration_signing_bytes,
};
use scp_relay_client::code;

/// The push message a [`PushSignatureVerifier`] checks.
#[derive(Debug, Clone, Copy)]
pub enum PushMessage<'a> {
    /// A `PushRegistration` (§22.11.4), signed under `"SCP-PUSH-REGISTER-V1:"`.
    Registration(&'a PushRegistration),
    /// A `PushDeregistration` (§22.11.4), signed under
    /// `"SCP-PUSH-DEREGISTER-V1:"`.
    Deregistration(&'a PushDeregistration),
}

impl PushMessage<'_> {
    /// The identifier that claims to have signed the message.
    #[must_use]
    pub const fn registrant(&self) -> &DID {
        match self {
            Self::Registration(m) => &m.registrant,
            Self::Deregistration(m) => &m.registrant,
        }
    }

    /// The message's 64-byte P-256 signature (`r || s`).
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        match self {
            Self::Registration(m) => &m.signature,
            Self::Deregistration(m) => &m.signature,
        }
    }

    /// Builds the message's §9.5.2 signature preimage for the relay at
    /// `relay_url`, through the one signing-bytes function of its type.
    ///
    /// # Errors
    ///
    /// Returns [`PushVerifyError::Malformed`] carrying the
    /// [`PushMessageError`] of the signing-bytes function.
    pub fn signing_bytes(&self, relay_url: &str) -> Result<Vec<u8>, PushVerifyError> {
        match self {
            Self::Registration(m) => push_registration_signing_bytes(m, relay_url),
            Self::Deregistration(m) => push_deregistration_signing_bytes(m, relay_url),
        }
        .map_err(PushVerifyError::Malformed)
    }
}

/// Why a [`PushSignatureVerifier`] refused a push message.
///
/// Every variant maps to one ADR-004 wire code through
/// [`PushVerifyError::wire_code`]. A relay that receives any variant stores
/// nothing and changes no registration (§10.7.1, ADR-004).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PushVerifyError {
    /// The registrant's identifier does not resolve to a key-event log.
    #[error("push registrant identifier does not resolve")]
    IdentifierUnresolvable,
    /// The registrant's key-state resolution was inconclusive. The condition
    /// is transient, and the client may retry.
    #[error("push registrant key state is unavailable")]
    KeyStateUnavailable,
    /// The signature does not verify against the key that verification
    /// selected, including a signature over another relay's canonical URL.
    #[error("push message signature does not verify")]
    SignatureInvalid,
    /// The key that verifies the signature is not `Current` in the `#active`
    /// role at the latest state-carrying event (§9.7.4.2 R8).
    #[error("push message signing key is not Current in #active")]
    NotCurrentActive,
    /// The message breaks a §22.11.4 field rule, so no preimage exists for it.
    #[error("push message is malformed: {0}")]
    Malformed(#[source] PushMessageError),
    /// No verifier that can check a push signature against a key state is
    /// available. Only [`KelPushVerifier`] returns it, before the keri
    /// workstream replaces its body; that body never returns it.
    #[error("push signature verifier is unavailable")]
    VerifierUnavailable,
}

impl PushVerifyError {
    /// The ADR-004 wire code a relay answers this rejection with.
    ///
    /// `4060` `PUSH_REGISTRATION_REJECTED` for an unresolvable identifier, an
    /// invalid signature, a key not `Current` in `#active`, and a malformed
    /// message; `5004` `PUSH_KEY_STATE_UNAVAILABLE` for unavailable key state;
    /// `5003` `PUSH_VERIFIER_UNAVAILABLE` for an unavailable verifier. A relay
    /// also answers `5004` when a verifier call exceeds its timeout, which
    /// produces no `PushVerifyError`.
    #[must_use]
    pub const fn wire_code(&self) -> u16 {
        match self {
            Self::IdentifierUnresolvable
            | Self::SignatureInvalid
            | Self::NotCurrentActive
            | Self::Malformed(_) => code::PUSH_REGISTRATION_REJECTED,
            Self::KeyStateUnavailable => code::PUSH_KEY_STATE_UNAVAILABLE,
            Self::VerifierUnavailable => code::PUSH_VERIFIER_UNAVAILABLE,
        }
    }
}

/// Verifies the signature of a push message for one relay (§10.7.1 step 3).
///
/// The relay holds an `Arc<dyn PushSignatureVerifier>` (ADR-062).
#[async_trait::async_trait]
pub trait PushSignatureVerifier: Debug + Send + Sync {
    /// Verifies `message`'s signature for the relay whose URL is `relay_url`.
    ///
    /// `relay_url` is the URL from which the relay derived the reserved push
    /// routing ID the PUBLISH arrived at, never a URL the client supplied
    /// (§10.7.1 step 3). An implementation builds the preimage with
    /// [`PushMessage::signing_bytes`] and checks the signature over the
    /// SHA-256 of those bytes.
    ///
    /// # Errors
    ///
    /// Returns the [`PushVerifyError`] that names the rejection. `Ok` means
    /// the signature verifies against the key the registrant's key state lists
    /// `Current` in the `#active` role.
    async fn verify(
        &self,
        message: PushMessage<'_>,
        relay_url: &str,
    ) -> Result<DID, PushVerifyError>;
}

/// The production push signature verifier, which resolves the registrant's
/// key state from its key-event log (§9.7.4.2 R2, R3, R8).
///
/// Startup wires this verifier whenever push is enabled. Until the keri
/// workstream builds its body, it refuses every message with
/// [`PushVerifyError::VerifierUnavailable`], so the relay answers `5003` and
/// accepts no push message.
#[derive(Debug, Clone, Copy, Default)]
pub struct KelPushVerifier;

#[async_trait::async_trait]
impl PushSignatureVerifier for KelPushVerifier {
    async fn verify(
        &self,
        _message: PushMessage<'_>,
        _relay_url: &str,
    ) -> Result<DID, PushVerifyError> {
        // Stub — see PUSH-005. The keri workstream replaces this body with
        // key-state resolution after SCP-308 S1; until then the verifier
        // refuses every message and never accepts one.
        Err(PushVerifyError::VerifierUnavailable)
    }
}

#[cfg(any(test, feature = "testing"))]
pub use test_verifier::TestPushVerifier;

#[cfg(any(test, feature = "testing"))]
mod test_verifier {
    use std::collections::HashMap;

    use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
    use scp_did::DID;
    use sha2::{Digest, Sha256};

    use super::{PushMessage, PushSignatureVerifier, PushVerifyError};

    /// A test verifier that checks a real P-256 signature against the key the
    /// test supplies for each registrant.
    ///
    /// Compiled only under `cfg(test)` or the `testing` feature, so no shipped
    /// build contains it. It never accepts a message whose signature it has
    /// not verified: a registrant it holds no key for is
    /// [`PushVerifyError::IdentifierUnresolvable`], and a signature that does
    /// not verify under the strict §9.5.1 rule (low `s` included) is
    /// [`PushVerifyError::SignatureInvalid`].
    #[derive(Debug, Clone)]
    pub struct TestPushVerifier {
        keys: HashMap<DID, P256PublicKey>,
    }

    impl TestPushVerifier {
        /// Builds a verifier that holds `keys`, each the `Current` `#active`
        /// key of its registrant.
        #[must_use]
        pub fn new(keys: impl IntoIterator<Item = (DID, P256PublicKey)>) -> Self {
            Self {
                keys: keys.into_iter().collect(),
            }
        }
    }

    #[async_trait::async_trait]
    impl PushSignatureVerifier for TestPushVerifier {
        async fn verify(
            &self,
            message: PushMessage<'_>,
            relay_url: &str,
        ) -> Result<DID, PushVerifyError> {
            let preimage = message.signing_bytes(relay_url)?;
            let registrant = message.registrant();
            let key = self
                .keys
                .get(registrant)
                .ok_or(PushVerifyError::IdentifierUnresolvable)?;
            let digest: [u8; 32] = Sha256::digest(&preimage).into();
            verify_prehash_strict(key, &digest, message.signature())
                .map_err(|_| PushVerifyError::SignatureInvalid)?;
            Ok(registrant.clone())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use scp_crypto::p256::{P256SecretKey, sign_prehash_rfc6979, verify_prehash_lenient};
    use scp_protocol::discovery::push::PushPlatform;
    use sha2::{Digest, Sha256};

    use super::*;

    const RELAY: &str = "wss://relay.example";
    const OTHER_RELAY: &str = "wss://other.example";
    const REGISTRANT: &str = "did:dht:z6Mkp5HpCyHSafDFTtqRzbKWJsxVLaGz1sQojsLVQfHQ9u8m";

    fn secret(seed: u8) -> P256SecretKey {
        P256SecretKey::from_scalar_bytes(&[seed; 32]).unwrap()
    }

    fn sign(key: &P256SecretKey, preimage: &[u8]) -> [u8; 64] {
        let digest: [u8; 32] = Sha256::digest(preimage).into();
        sign_prehash_rfc6979(key, &digest).unwrap()
    }

    fn registration(key: &P256SecretKey, relay_url: &str) -> PushRegistration {
        let mut msg = PushRegistration {
            registrant: DID::from(REGISTRANT),
            platform: PushPlatform::Apns,
            token: vec![0xA1, 0xB2, 0xC3],
            routing_ids: vec![[0x11; 32], [0x22; 32]],
            timestamp: 1_700_000_000,
            signature: [0; 64],
        };
        msg.signature = sign(
            key,
            &push_registration_signing_bytes(&msg, relay_url).unwrap(),
        );
        msg
    }

    fn deregistration(key: &P256SecretKey, relay_url: &str) -> PushDeregistration {
        let mut msg = PushDeregistration {
            registrant: DID::from(REGISTRANT),
            platform: PushPlatform::Fcm,
            token: vec![0xD4, 0xE5],
            timestamp: 1_700_000_100,
            signature: [0; 64],
        };
        msg.signature = sign(
            key,
            &push_deregistration_signing_bytes(&msg, relay_url).unwrap(),
        );
        msg
    }

    /// The verifier the relay holds: a trait object behind `Arc` (ADR-062).
    fn test_verifier(key: &P256SecretKey) -> Arc<dyn PushSignatureVerifier> {
        Arc::new(TestPushVerifier::new([(
            DID::from(REGISTRANT),
            key.public_key(),
        )]))
    }

    #[tokio::test]
    async fn stub_rejects_validly_signed_messages_with_5003() {
        let key = secret(7);
        let reg = registration(&key, RELAY);
        let dereg = deregistration(&key, RELAY);
        // Control: the test verifier accepts both, so the stub's refusal is
        // not caused by a bad signature.
        let control = test_verifier(&key);
        assert!(
            control
                .verify(PushMessage::Registration(&reg), RELAY)
                .await
                .is_ok()
        );
        assert!(
            control
                .verify(PushMessage::Deregistration(&dereg), RELAY)
                .await
                .is_ok()
        );

        let stub: Arc<dyn PushSignatureVerifier> = Arc::new(KelPushVerifier);
        for message in [
            PushMessage::Registration(&reg),
            PushMessage::Deregistration(&dereg),
        ] {
            let err = stub.verify(message, RELAY).await.unwrap_err();
            assert_eq!(err, PushVerifyError::VerifierUnavailable);
            assert_eq!(err.wire_code(), 5003);
        }
    }

    #[tokio::test]
    async fn stub_rejects_malformed_and_unsigned_messages_with_verifier_unavailable() {
        let key = secret(7);
        let mut empty_routes = registration(&key, RELAY);
        empty_routes.routing_ids.clear();
        let mut unsigned = registration(&key, RELAY);
        unsigned.signature = [0; 64];
        let stub = KelPushVerifier;
        for (message, url) in [
            (PushMessage::Registration(&empty_routes), RELAY),
            (PushMessage::Registration(&unsigned), RELAY),
            (PushMessage::Registration(&unsigned), "not a url"),
        ] {
            assert_eq!(
                stub.verify(message, url).await,
                Err(PushVerifyError::VerifierUnavailable)
            );
        }
    }

    #[tokio::test]
    async fn test_verifier_accepts_messages_signed_by_the_supplied_key() {
        let key = secret(7);
        let verifier = test_verifier(&key);
        let reg = registration(&key, RELAY);
        let dereg = deregistration(&key, RELAY);
        assert_eq!(
            verifier
                .verify(PushMessage::Registration(&reg), RELAY)
                .await,
            Ok(DID::from(REGISTRANT))
        );
        // Every spelling of the relay URL canonicalizes to one preimage.
        assert_eq!(
            verifier
                .verify(
                    PushMessage::Deregistration(&dereg),
                    "WSS://Relay.Example:443/"
                )
                .await,
            Ok(DID::from(REGISTRANT))
        );
    }

    #[tokio::test]
    async fn test_verifier_rejects_a_signature_made_for_another_relay_url() {
        let key = secret(7);
        let verifier = test_verifier(&key);
        let reg = registration(&key, OTHER_RELAY);
        let dereg = deregistration(&key, OTHER_RELAY);
        assert_eq!(
            verifier
                .verify(PushMessage::Registration(&reg), RELAY)
                .await,
            Err(PushVerifyError::SignatureInvalid)
        );
        assert_eq!(
            verifier
                .verify(PushMessage::Deregistration(&dereg), RELAY)
                .await,
            Err(PushVerifyError::SignatureInvalid)
        );
    }

    #[tokio::test]
    async fn test_verifier_rejects_each_tampered_field() {
        let key = secret(7);
        let verifier = test_verifier(&key);
        let signed = registration(&key, RELAY);
        let tampers: [fn(&mut PushRegistration); 5] = [
            |m| m.platform = PushPlatform::Fcm,
            |m| m.token.push(0x00),
            |m| m.routing_ids[1][0] ^= 1,
            |m| m.timestamp += 1,
            |m| m.signature[10] ^= 1,
        ];
        for tamper in tampers {
            let mut msg = signed.clone();
            tamper(&mut msg);
            assert_eq!(
                verifier
                    .verify(PushMessage::Registration(&msg), RELAY)
                    .await,
                Err(PushVerifyError::SignatureInvalid)
            );
        }

        let signed = deregistration(&key, RELAY);
        let tampers: [fn(&mut PushDeregistration); 3] = [
            |m| m.platform = PushPlatform::Apns,
            |m| m.token[0] ^= 1,
            |m| m.timestamp -= 1,
        ];
        for tamper in tampers {
            let mut msg = signed.clone();
            tamper(&mut msg);
            assert_eq!(
                verifier
                    .verify(PushMessage::Deregistration(&msg), RELAY)
                    .await,
                Err(PushVerifyError::SignatureInvalid)
            );
        }
    }

    #[tokio::test]
    async fn test_verifier_rejects_a_message_signed_by_another_key() {
        let verifier = test_verifier(&secret(7));
        let wrong = secret(9);
        assert_eq!(
            verifier
                .verify(
                    PushMessage::Registration(&registration(&wrong, RELAY)),
                    RELAY
                )
                .await,
            Err(PushVerifyError::SignatureInvalid)
        );
        assert_eq!(
            verifier
                .verify(
                    PushMessage::Deregistration(&deregistration(&wrong, RELAY)),
                    RELAY
                )
                .await,
            Err(PushVerifyError::SignatureInvalid)
        );
    }

    #[tokio::test]
    async fn test_verifier_rejects_an_unchecked_or_high_s_signature() {
        let key = secret(7);
        let verifier = test_verifier(&key);
        let mut msg = registration(&key, RELAY);
        msg.signature = [0; 64];
        assert_eq!(
            verifier
                .verify(PushMessage::Registration(&msg), RELAY)
                .await,
            Err(PushVerifyError::SignatureInvalid)
        );

        // The high-s twin (r, n - s) of a valid signature verifies under plain
        // ECDSA; §9.5 requires the verifier to reject it.
        let msg = registration(&key, RELAY);
        let mut high = msg.clone();
        high.signature = high_s_twin(&msg.signature);
        assert_ne!(high.signature, msg.signature);
        let digest: [u8; 32] =
            Sha256::digest(push_registration_signing_bytes(&high, RELAY).unwrap()).into();
        assert!(
            verify_prehash_lenient(&key.public_key(), &digest, &high.signature).is_ok(),
            "the twin must be a valid high-s signature for the test to mean anything"
        );
        assert_eq!(
            verifier
                .verify(PushMessage::Registration(&high), RELAY)
                .await,
            Err(PushVerifyError::SignatureInvalid)
        );
    }

    /// Returns `(r, n - s)` for a low-s signature `(r, s)`.
    fn high_s_twin(sig: &[u8; 64]) -> [u8; 64] {
        // The P-256 group order n, big-endian.
        const N: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
            0xFC, 0x63, 0x25, 0x51,
        ];
        let mut out = *sig;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = i16::from(N[i]) - i16::from(sig[32 + i]) - borrow;
            borrow = i16::from(diff < 0);
            out[32 + i] = u8::try_from(diff.rem_euclid(256)).unwrap();
        }
        out
    }

    #[tokio::test]
    async fn test_verifier_rejects_an_unknown_registrant_as_unresolvable() {
        let key = secret(7);
        let verifier =
            TestPushVerifier::new([(DID::from("did:dht:someone-else"), key.public_key())]);
        assert_eq!(
            verifier
                .verify(PushMessage::Registration(&registration(&key, RELAY)), RELAY)
                .await,
            Err(PushVerifyError::IdentifierUnresolvable)
        );
    }

    #[tokio::test]
    async fn test_verifier_rejects_malformed_messages_before_any_key_lookup() {
        let key = secret(7);
        let verifier = test_verifier(&key);
        let mut msg = registration(&key, RELAY);
        msg.routing_ids.clear();
        assert_eq!(
            verifier
                .verify(PushMessage::Registration(&msg), RELAY)
                .await,
            Err(PushVerifyError::Malformed(
                PushMessageError::EmptyRoutingIds
            ))
        );
        let mut msg = deregistration(&key, RELAY);
        msg.token.clear();
        assert_eq!(
            verifier
                .verify(PushMessage::Deregistration(&msg), RELAY)
                .await,
            Err(PushVerifyError::Malformed(PushMessageError::EmptyToken))
        );
    }

    #[test]
    fn wire_code_maps_every_variant_to_its_adr_004_code() {
        let cases = [
            (PushVerifyError::IdentifierUnresolvable, 4060),
            (PushVerifyError::KeyStateUnavailable, 5004),
            (PushVerifyError::SignatureInvalid, 4060),
            (PushVerifyError::NotCurrentActive, 4060),
            (
                PushVerifyError::Malformed(PushMessageError::EmptyRoutingIds),
                4060,
            ),
            (PushVerifyError::VerifierUnavailable, 5003),
        ];
        for (err, expected) in cases {
            // Exhaustive match: a new variant fails to compile here until it
            // gets a row above.
            match err {
                PushVerifyError::IdentifierUnresolvable
                | PushVerifyError::KeyStateUnavailable
                | PushVerifyError::SignatureInvalid
                | PushVerifyError::NotCurrentActive
                | PushVerifyError::Malformed(_)
                | PushVerifyError::VerifierUnavailable => {}
            }
            assert_eq!(err.wire_code(), expected, "{err:?}");
        }
    }

    /// Indicator for "no verifier returns `Ok` without checking a signature":
    /// every `impl PushSignatureVerifier for` in the workspace's sources names
    /// one of the two reviewed verifiers. A new implementation fails this test
    /// until a reviewer adds it here, after reading that it checks a signature
    /// before it returns `Ok`.
    #[test]
    fn only_the_reviewed_verifiers_implement_the_trait() {
        const NEEDLE: &str = concat!("PushSignatureVerifier", " for ");
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let mut implementors = Vec::new();
        let mut stack = vec![crates.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    if path.file_name().is_some_and(|n| n != "target") {
                        stack.push(path);
                    }
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let source = std::fs::read_to_string(&path).unwrap();
                    implementors.extend(source.split(NEEDLE).skip(1).filter_map(|rest| {
                        let name: String = rest
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                        name.starts_with(char::is_uppercase).then_some(name)
                    }));
                }
            }
        }
        implementors.sort();
        assert_eq!(implementors, ["KelPushVerifier", "TestPushVerifier"]);
    }
}
