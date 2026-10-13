//! The challenge operations the three bridges share (spec 07 §7.3.4, ADR-017).
//!
//! A bridge resolves the verifier identity to its `#active` [`CommandSigner`]
//! and its instance resolver, then calls [`create_challenge`] or
//! [`verify_response_and_sign`]. Custody signs the 32-byte digest of each
//! canonical preimage; the private key never leaves custody.

use std::sync::Arc;

use scp_core::context::ContextError;
use scp_core::context::actor::signer::{CommandSigner, sign_bounded};
use scp_core::trust::attestation::ActiveKeyResolver;
use scp_core::trust::{
    ChallengeRequest, ChallengeResponse, ChallengeVerification, TestCase, TrustError,
    challenge_request_unsigned, check_challenge_response,
};
use scp_did::DID;

/// The caller-supplied JSON argument of a challenge operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonInput {
    /// `test_cases_json`: a JSON array of `TestCase`.
    TestCases,
    /// `challenge_json`: a signed `ChallengeRequest`.
    Challenge,
    /// `response_json`: a `ChallengeResponse`.
    Response,
}

impl std::fmt::Display for JsonInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TestCases => "test_cases_json",
            Self::Challenge => "challenge_json",
            Self::Response => "response_json",
        })
    }
}

/// Why a challenge operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ChallengeOpError {
    /// A caller-supplied JSON argument does not decode to its type. Every
    /// bridge reports it as `SCP-VALID-7002`, whichever argument it is.
    #[error("failed to parse {input}: {reason}")]
    MalformedJson {
        /// Which argument failed to decode.
        input: JsonInput,
        /// The decoder's message.
        reason: String,
    },
    /// The protocol refused the request, the response or the record.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// The verifier's signer refused, timed out, or is not Ed25519.
    #[error(transparent)]
    Sign(#[from] ContextError),
}

/// Builds a challenge request from the challenger-written `test_cases_json`
/// and signs it with the verifier's `#active` key through `signer`.
///
/// # Errors
///
/// - [`ChallengeOpError::Sign`] with [`ContextError::CryptoFailed`] when the
///   signer is not Ed25519, checked before anything else so no custody call
///   is made; otherwise the custody failure from signing.
/// - [`ChallengeOpError::MalformedJson`] when `test_cases_json` does not
///   parse.
/// - [`ChallengeOpError::Trust`] for every refusal of
///   [`challenge_request_unsigned`], including
///   [`TrustError::ChallengeSuiteBelowMinimum`].
pub async fn create_challenge(
    signer: &CommandSigner,
    verifier: DID,
    subject: DID,
    capability_uri: String,
    test_cases_json: &str,
    timeout_secs: u32,
) -> Result<ChallengeRequest, ChallengeOpError> {
    signer.require_ed25519()?;
    let test_cases: Vec<TestCase> =
        decode(JsonInput::TestCases, serde_json::from_str(test_cases_json))?;
    let unsigned =
        challenge_request_unsigned(verifier, subject, capability_uri, test_cases, timeout_secs)?;
    let signature = sign_bounded(signer, &unsigned.signing_digest()).await?;
    Ok(unsigned.with_verifier_signature(signature.to_vec()))
}

/// Names the `input` argument on a failed decode of it.
fn decode<T>(input: JsonInput, parsed: serde_json::Result<T>) -> Result<T, ChallengeOpError> {
    parsed.map_err(|e| ChallengeOpError::MalformedJson {
        input,
        reason: e.to_string(),
    })
}

/// The decoded arguments of [`verify_response_and_sign`].
///
/// Only [`VerifyInputs::decode`] builds one, so every bridge decodes the
/// caller's JSON here and reports a malformed argument with one code.
#[derive(Debug)]
pub struct VerifyInputs {
    request: ChallengeRequest,
    response: ChallengeResponse,
}

impl VerifyInputs {
    /// Decodes the signed request in `challenge_json` and the response in
    /// `response_json`. A bridge calls this before it resolves any identity,
    /// so a malformed argument fails as such whoever the verifier is.
    ///
    /// # Errors
    ///
    /// [`ChallengeOpError::MalformedJson`] naming the first argument that
    /// does not decode, the challenge before the response.
    pub fn decode(challenge_json: &str, response_json: &str) -> Result<Self, ChallengeOpError> {
        Ok(Self {
            request: decode(JsonInput::Challenge, serde_json::from_str(challenge_json))?,
            response: decode(JsonInput::Response, serde_json::from_str(response_json))?,
        })
    }
}

/// Checks the response in `inputs` against its request and signs the
/// resulting record with the verifier's `#active` key through `signer`.
///
/// `resolver` resolves the request's verifier key and the response's
/// responder key. The bridges pass their instance's
/// `IdentityBackedDidResolver`, whose lookup blocks, so the check runs on a
/// blocking thread.
///
/// # Errors
///
/// - [`ChallengeOpError::Sign`] with [`ContextError::CryptoFailed`] when the
///   signer is not Ed25519, before any resolution or custody call; otherwise
///   the custody failure from signing.
/// - [`ChallengeOpError::Trust`] for every refusal of
///   [`check_challenge_response`], and
///   [`TrustError::KeyResolutionUnavailable`] when the resolver's backend is
///   unreachable.
pub async fn verify_response_and_sign<R>(
    signer: &CommandSigner,
    resolver: Arc<R>,
    verifier: DID,
    inputs: VerifyInputs,
    context_id: String,
) -> Result<ChallengeVerification, ChallengeOpError>
where
    R: ActiveKeyResolver + Send + Sync + 'static,
{
    signer.require_ed25519()?;
    let VerifyInputs { request, response } = inputs;
    let unsigned = tokio::task::spawn_blocking(move || {
        check_challenge_response(
            &request,
            &response,
            resolver.as_ref(),
            &scp_clock::SystemClock,
            &verifier,
            context_id,
        )
    })
    .await
    .map_err(|e| {
        ChallengeOpError::Sign(ContextError::CryptoFailed(format!(
            "challenge response check task failed: {e}"
        )))
    })??;
    let signature = sign_bounded(signer, &unsigned.signing_digest()).await?;
    Ok(unsigned.with_verifier_signature(signature.to_vec()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use scp_core::trust::{
        ChallengeType, ExpectedOutput, challenge_request_signing_digest,
        challenge_verification_signing_digest,
    };
    use scp_crypto::p256::P256SecretKey;
    use scp_crypto::{DynScpSigner, SigAlg, SignFuture};

    use super::*;

    /// A P-256 signer that counts every sign it is asked for.
    struct CountingP256 {
        key: P256SecretKey,
        signs: Arc<AtomicUsize>,
    }

    impl DynScpSigner for CountingP256 {
        fn algorithm(&self) -> SigAlg {
            DynScpSigner::algorithm(&self.key)
        }

        fn public_key(&self) -> Vec<u8> {
            DynScpSigner::public_key(&self.key)
        }

        fn sign_boxed<'a>(&'a self, digest: &'a [u8; 32]) -> SignFuture<'a> {
            self.signs.fetch_add(1, Ordering::SeqCst);
            self.key.sign_boxed(digest)
        }
    }

    fn p256_signer() -> (CommandSigner, Arc<AtomicUsize>) {
        let signs = Arc::new(AtomicUsize::new(0));
        let key = P256SecretKey::from_scalar_bytes(&[0x11; 32]).unwrap();
        let signer = CommandSigner::new(Arc::new(CountingP256 {
            key,
            signs: Arc::clone(&signs),
        }));
        (signer, signs)
    }

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn did(seed: u8) -> DID {
        scp_did::did_dht_from_public_key(&key(seed).verifying_key().to_bytes())
    }

    /// Resolves a did:dht to the key it was made from: the test keys are both
    /// identity and `#active` key.
    struct SeedResolver;

    impl ActiveKeyResolver for SeedResolver {
        fn resolve_active_key(&self, did_str: &str) -> Result<Vec<u8>, TrustError> {
            (1u8..=2)
                .find(|seed| did(*seed) == did_str)
                .map(|seed| key(seed).verifying_key().to_bytes().to_vec())
                .ok_or_else(|| TrustError::ChallengeSignatureInvalid {
                    challenge_id: String::new(),
                    reason: format!("unknown DID {did_str}"),
                })
        }
    }

    const URI: &str = "scp:capability:schema-validation/v1";

    fn cases_json(n: usize) -> String {
        let weight = 10_000 / n;
        let cases: Vec<TestCase> = (0..n)
            .map(|i| TestCase {
                test_id: format!("t{i}"),
                input: serde_json::json!({"i": i}),
                expected: ExpectedOutput::ExactMatch {
                    value: serde_json::json!({"ok": true}),
                },
                category: "basic".to_owned(),
                weight: u32::try_from(if i == 0 {
                    10_000 - weight * (n - 1)
                } else {
                    weight
                })
                .unwrap(),
            })
            .collect();
        serde_json::to_string(&cases).unwrap()
    }

    #[tokio::test]
    async fn create_challenge_rejects_p256_signer() {
        let (signer, signs) = p256_signer();
        let err = create_challenge(
            &signer,
            did(1),
            did(2),
            URI.to_owned(),
            &cases_json(20),
            300,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ChallengeOpError::Sign(ContextError::CryptoFailed(_))),
            "{err:?}"
        );
        assert_eq!(signs.load(Ordering::SeqCst), 0, "no custody call");
    }

    #[tokio::test]
    async fn verify_inputs_name_the_malformed_argument() {
        let request = create_challenge(
            &CommandSigner::local_ed25519(key(1)),
            did(1),
            did(2),
            URI.to_owned(),
            &cases_json(20),
            300,
        )
        .await
        .unwrap();
        let challenge_json = serde_json::to_string(&request).unwrap();
        for (challenge, response, expected) in [
            ("{\"not\": \"a challenge\"}", "[1, 2]", JsonInput::Challenge),
            (challenge_json.as_str(), "[1, 2]", JsonInput::Response),
        ] {
            let err = VerifyInputs::decode(challenge, response).unwrap_err();
            assert!(
                matches!(err, ChallengeOpError::MalformedJson { input, .. } if input == expected),
                "{err:?}"
            );
        }
    }

    #[tokio::test]
    async fn verify_response_and_sign_rejects_p256_signer() {
        let (signer, signs) = p256_signer();
        let request = create_challenge(
            &CommandSigner::local_ed25519(key(1)),
            did(1),
            did(2),
            URI.to_owned(),
            &cases_json(20),
            300,
        )
        .await
        .unwrap();
        let response = ChallengeResponse {
            challenge_id: hex::encode(request.challenge_id),
            responder_did: did(2),
            result: serde_json::json!({}),
            completed_at: 0,
            signature: Vec::new(),
        };
        let err = verify_response_and_sign(
            &signer,
            Arc::new(SeedResolver),
            did(1),
            VerifyInputs::decode(
                &serde_json::to_string(&request).unwrap(),
                &serde_json::to_string(&response).unwrap(),
            )
            .unwrap(),
            "ctx".to_owned(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ChallengeOpError::Sign(ContextError::CryptoFailed(_))),
            "{err:?}"
        );
        assert_eq!(signs.load(Ordering::SeqCst), 0, "no custody call");
    }

    #[tokio::test]
    async fn create_challenge_signs_request_digest() {
        let request = create_challenge(
            &CommandSigner::local_ed25519(key(1)),
            did(1),
            did(2),
            URI.to_owned(),
            &cases_json(20),
            300,
        )
        .await
        .unwrap();
        let digest = challenge_request_signing_digest(&request).unwrap();
        let signature: [u8; 64] = request.verifier_signature.as_slice().try_into().unwrap();
        key(1)
            .verifying_key()
            .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&signature))
            .unwrap();
    }

    #[tokio::test]
    async fn create_challenge_refuses_malformed_test_cases_json() {
        let err = create_challenge(
            &CommandSigner::local_ed25519(key(1)),
            did(1),
            did(2),
            URI.to_owned(),
            "{\"not\": \"an array\"}",
            300,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                ChallengeOpError::MalformedJson {
                    input: JsonInput::TestCases,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn create_challenge_refuses_suite_below_minimum() {
        let err = create_challenge(
            &CommandSigner::local_ed25519(key(1)),
            did(1),
            did(2),
            URI.to_owned(),
            &cases_json(19),
            300,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                ChallengeOpError::Trust(TrustError::ChallengeSuiteBelowMinimum {
                    minimum: 20,
                    supplied: 19,
                    ..
                })
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn verify_response_and_sign_signs_record_digest() {
        use ed25519_dalek::Signer;

        let request = create_challenge(
            &CommandSigner::local_ed25519(key(1)),
            did(1),
            did(2),
            URI.to_owned(),
            &cases_json(20),
            300,
        )
        .await
        .unwrap();
        let mut response = ChallengeResponse {
            challenge_id: hex::encode(request.challenge_id),
            responder_did: did(2),
            result: serde_json::json!({
                "passed": true, "score": 10_000, "test_count": 20, "pass_count": 20
            }),
            completed_at: scp_clock::Clock::now_secs(&scp_clock::SystemClock),
            signature: Vec::new(),
        };
        let bytes = scp_core::trust::canonical_challenge_response_bytes(&response).unwrap();
        response.signature = key(2).sign(&bytes).to_bytes().to_vec();

        let record = verify_response_and_sign(
            &CommandSigner::local_ed25519(key(1)),
            Arc::new(SeedResolver),
            did(1),
            VerifyInputs::decode(
                &serde_json::to_string(&request).unwrap(),
                &serde_json::to_string(&response).unwrap(),
            )
            .unwrap(),
            "ctx-1".to_owned(),
        )
        .await
        .unwrap();
        assert_eq!(record.subject, did(2));
        assert_eq!(record.context_id.as_deref(), Some("ctx-1"));
        assert!(matches!(
            record.verification_method,
            scp_core::trust::VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::Uri(_)
            }
        ));
        let digest = challenge_verification_signing_digest(&record).unwrap();
        let signature: [u8; 64] = record.verifier_signature.as_slice().try_into().unwrap();
        key(1)
            .verifying_key()
            .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&signature))
            .unwrap();
    }
}
