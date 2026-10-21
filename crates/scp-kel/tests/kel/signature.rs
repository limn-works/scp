//! `verify_indexed` and `IndexedSignature::read` against spec 25 Vectors 41
//! and 42 and one negative per check (`09-security-model.md` §9.7.4.2,
//! "Signature form").
//!
//! Every negative that does not test the signature itself is re-signed with
//! §25.2's reference key, Vector 41's root member 0, so the asserted variant
//! is the only check the input fails.

use scp_crypto::p256::{P256Error, P256SecretKey, SeedLabel, sign_prehash_rfc6979};
use scp_kel::{
    AssertionSignature, ClientDataError, IndexedSignature, IndexedSignatureError,
    IndexedSignaturePart, IndexedSignatureReadError, SignatureForm, key_event_challenge,
    parse_client_data_json, verify_indexed,
};
use sha2::{Digest, Sha256};

use crate::fixtures::{
    TestResult, V41_ACTIVE, V41_DIGEST, V41_ROOT, V41_SIGNATURE, V42_AUTHENTICATOR_DATA,
    V42_CHALLENGE, V42_CHALLENGE_BYTES, V42_CLIENT_DATA_HASH, V42_CLIENT_DATA_JSON,
    V42_CLIENT_DATA_JSON_HEX, V42_DIGEST, V42_INDEXED_SIGNATURE, V42_RP_ID, V42_SIGNATURE,
    V42_SIGNED_DIGEST, V42_SIGNED_MESSAGE, array, bytes,
};

type Error = Box<dyn std::error::Error>;

/// The P-256 group order n, big-endian.
const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

/// §25.2's reference scalar seed; its key is Vector 41's root member 0.
const REFERENCE_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn signer() -> Result<P256SecretKey, Error> {
    Ok(P256SecretKey::from_seed(
        SeedLabel::TestVectorKey,
        &array(REFERENCE_SEED)?,
    ))
}

fn root() -> Result<[u8; 33], Error> {
    array(V41_ROOT)
}

fn v42_digest() -> Result<[u8; 32], Error> {
    array(V42_DIGEST)
}

/// The `clientDataJSON` an authenticator emits for `client_data_type` and
/// `challenge`, with Vector 42's origin members.
fn client_data(client_data_type: &str, challenge: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{client_data_type}","challenge":"{challenge}","origin":"https://ctx.network","crossOrigin":false}}"#
    )
    .into_bytes()
}

/// Vector 42's `authenticatorData` with its flags byte replaced.
fn authenticator_data(flags: u8) -> Result<Vec<u8>, Error> {
    let mut data = bytes(V42_AUTHENTICATOR_DATA)?;
    *data.get_mut(32).ok_or("short authenticatorData")? = flags;
    Ok(data)
}

/// The signature the reference key makes over an assertion's message,
/// `SHA-256(authenticatorData || SHA-256(clientDataJSON))`.
fn sign_assertion(authenticator: &[u8], client_data_json: &[u8]) -> Result<[u8; 64], Error> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(authenticator)
        .chain_update(Sha256::digest(client_data_json))
        .finalize()
        .into();
    Ok(sign_prehash_rfc6979(&signer()?, &digest)?)
}

/// An assertion over `client_data_json` that the reference key signed.
fn resigned(authenticator: Vec<u8>, client_data_json: Vec<u8>) -> Result<IndexedSignature, Error> {
    let signature = sign_assertion(&authenticator, &client_data_json)?;
    Ok(IndexedSignature::WebAuthnAssertion(
        AssertionSignature::new(authenticator, client_data_json, signature)?,
    ))
}

/// The wire bytes of an assertion whose parts no constructor checked.
fn assertion_wire(authenticator: &[u8], client_data_json: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in [authenticator, client_data_json] {
        out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(signature);
    out
}

/// Verifies an assertion against Vector 42's digest under member 0, with
/// the assertion form declared.
fn verify_v42(signature: &IndexedSignature) -> Result<Result<(), IndexedSignatureError>, Error> {
    Ok(verify_indexed(
        &root()?,
        &v42_digest()?,
        SignatureForm::WebAuthnAssertion,
        signature,
    ))
}

/// Verifies a raw-form signature under member 0, with the raw form
/// declared.
fn verify_raw(
    key: &[u8; 33],
    digest: &[u8; 32],
    signature: [u8; 64],
) -> Result<(), IndexedSignatureError> {
    verify_indexed(
        key,
        digest,
        SignatureForm::Raw,
        &IndexedSignature::Raw { signature },
    )
}

/// `n − s` for a big-endian 32-byte `s`.
fn negate_scalar(s: &[u8]) -> Result<[u8; 32], Error> {
    let order = array::<32>(ORDER)?;
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let a = i16::from(*order.get(i).ok_or("order")?);
        let b = i16::from(*s.get(i).ok_or("short s")?);
        let mut diff = a - b - borrow;
        borrow = 0;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        }
        *out.get_mut(i).ok_or("index")? = u8::try_from(diff)?;
    }
    Ok(out)
}

/// A signature with `s` replaced by `n − s`.
fn high_s(signature: &[u8; 64]) -> Result<[u8; 64], Error> {
    let mut out = *signature;
    let negated = negate_scalar(signature.get(32..).ok_or("short")?)?;
    out.get_mut(32..).ok_or("short")?.copy_from_slice(&negated);
    Ok(out)
}

#[test]
fn vector_41_raw_form_reads_and_verifies() -> TestResult {
    let field = bytes(V41_SIGNATURE)?;
    let (signature, consumed) = IndexedSignature::read(SignatureForm::Raw, &field)?;
    assert_eq!(consumed, 64);
    assert_eq!(signature.form(), SignatureForm::Raw);
    assert_eq!(signature.to_bytes(), field);
    verify_indexed(
        &root()?,
        &array(V41_DIGEST)?,
        SignatureForm::Raw,
        &signature,
    )?;
    Ok(())
}

#[test]
fn vector_42_assertion_form_reproduces_every_intermediate_and_verifies() -> TestResult {
    let field = bytes(V42_INDEXED_SIGNATURE)?;
    assert_eq!(field.len(), 264);
    let (signature, consumed) = IndexedSignature::read(SignatureForm::WebAuthnAssertion, &field)?;
    assert_eq!(consumed, 264);
    assert_eq!(signature.to_bytes(), field);
    let IndexedSignature::WebAuthnAssertion(assertion) = &signature else {
        return Err("Vector 42 read as the raw form".into());
    };
    assert_eq!(
        assertion.authenticator_data(),
        bytes(V42_AUTHENTICATOR_DATA)?
    );
    assert_eq!(
        assertion.client_data_json(),
        V42_CLIENT_DATA_JSON.as_bytes()
    );
    assert_eq!(
        assertion.client_data_json(),
        bytes(V42_CLIENT_DATA_JSON_HEX)?
    );
    assert_eq!(assertion.client_data_json().len(), 155);
    assert_eq!(assertion.signature(), &array::<64>(V42_SIGNATURE)?);

    // authenticatorData from its stated derivation: rpIdHash =
    // SHA-256("ctx.network"), flags 0x05 (UP and UV), signCount 0.
    let authenticator = assertion.authenticator_data();
    assert_eq!(
        authenticator.get(..32).ok_or("short authenticatorData")?,
        Sha256::digest(V42_RP_ID.as_bytes()).as_slice()
    );
    assert_eq!(authenticator.get(32), Some(&0x05));
    assert_eq!(authenticator.get(33..), Some(&[0u8; 4][..]));

    let digest = v42_digest()?;
    assert_eq!(
        key_event_challenge(&digest).as_slice(),
        bytes(V42_CHALLENGE_BYTES)?
    );
    let members = parse_client_data_json(assertion)?;
    assert_eq!(members.client_data_type, "webauthn.get");
    assert_eq!(members.challenge, V42_CHALLENGE);

    let client_data_hash: [u8; 32] = Sha256::digest(assertion.client_data_json()).into();
    assert_eq!(client_data_hash, array::<32>(V42_CLIENT_DATA_HASH)?);
    let mut message = authenticator.to_vec();
    message.extend_from_slice(&client_data_hash);
    assert_eq!(message.len(), 69);
    assert_eq!(message, bytes(V42_SIGNED_MESSAGE)?);
    let signed: [u8; 32] = Sha256::digest(&message).into();
    assert_eq!(signed, array::<32>(V42_SIGNED_DIGEST)?);

    verify_v42(&signature)??;
    // The assertion signs its own envelope, never D: the same 64 bytes do
    // not verify as a raw-form signature over D.
    assert_eq!(
        verify_raw(&root()?, &digest, *assertion.signature()),
        Err(IndexedSignatureError::Signature(
            P256Error::VerificationFailed
        ))
    );
    Ok(())
}

/// (a) Vector 41 with s replaced by n − s.
#[test]
fn raw_form_rejects_high_s() -> TestResult {
    assert_eq!(
        verify_raw(
            &root()?,
            &array(V41_DIGEST)?,
            high_s(&array(V41_SIGNATURE)?)?
        ),
        Err(IndexedSignatureError::Signature(P256Error::HighS))
    );
    Ok(())
}

/// (a′) Vector 42 with s replaced by n − s, re-enveloped.
#[test]
fn assertion_form_rejects_high_s() -> TestResult {
    let signature = IndexedSignature::WebAuthnAssertion(AssertionSignature::new(
        bytes(V42_AUTHENTICATOR_DATA)?,
        V42_CLIENT_DATA_JSON.as_bytes().to_vec(),
        high_s(&array(V42_SIGNATURE)?)?,
    )?);
    assert_eq!(
        verify_v42(&signature)?,
        Err(IndexedSignatureError::Signature(P256Error::HighS))
    );
    Ok(())
}

/// (b) r = 0 and (c) s = n: §9.5's one scalar-range check.
#[test]
fn raw_form_rejects_scalars_out_of_range() -> TestResult {
    let original = array::<64>(V41_SIGNATURE)?;
    let mut zero_r = original;
    zero_r.get_mut(..32).ok_or("short")?.fill(0);
    let mut s_is_n = original;
    s_is_n
        .get_mut(32..)
        .ok_or("short")?
        .copy_from_slice(&array::<32>(ORDER)?);
    for signature in [zero_r, s_is_n] {
        assert_eq!(
            verify_raw(&root()?, &array(V41_DIGEST)?, signature),
            Err(IndexedSignatureError::Signature(
                P256Error::SignatureScalarOutOfRange
            ))
        );
    }
    Ok(())
}

/// (d) the wrong key and (e) a flipped digest bit.
#[test]
fn raw_form_rejects_wrong_key_and_wrong_digest() -> TestResult {
    let signature = array(V41_SIGNATURE)?;
    let failed = Err(IndexedSignatureError::Signature(
        P256Error::VerificationFailed,
    ));
    assert_eq!(
        verify_raw(&array(V41_ACTIVE)?, &array(V41_DIGEST)?, signature),
        failed
    );
    let mut digest = array::<32>(V41_DIGEST)?;
    *digest.get_mut(31).ok_or("short")? ^= 0x01;
    assert_eq!(verify_raw(&root()?, &digest, signature), failed);
    Ok(())
}

/// A39's per-index half: a key that is not a valid point fails typed.
#[test]
fn an_invalid_point_at_the_index_fails_typed() -> TestResult {
    let mut key = root()?;
    key[0] = 0x05;
    assert_eq!(
        verify_raw(&key, &array(V41_DIGEST)?, array(V41_SIGNATURE)?),
        Err(IndexedSignatureError::InvalidKey(
            P256Error::InvalidPointPrefix {
                len: 33,
                prefix: 0x05
            }
        ))
    );
    Ok(())
}

/// (f) UP clear (flags 0x04) and (g) UV clear (flags 0x01), each re-signed.
#[test]
fn assertion_form_requires_both_flags() -> TestResult {
    let challenge = client_data("webauthn.get", V42_CHALLENGE);
    let presence_clear = resigned(authenticator_data(0x04)?, challenge.clone())?;
    assert_eq!(
        verify_v42(&presence_clear)?,
        Err(IndexedSignatureError::UserPresenceNotSet)
    );
    let verification_clear = resigned(authenticator_data(0x01)?, challenge)?;
    assert_eq!(
        verify_v42(&verification_clear)?,
        Err(IndexedSignatureError::UserVerificationNotSet)
    );
    Ok(())
}

/// (t) flags 0x1D and (u) flags 0x45 carry both flags among others, and
/// verify.
#[test]
fn assertion_form_accepts_other_flag_bits_beside_up_and_uv() -> TestResult {
    for flags in [0x1D, 0x45] {
        let signature = resigned(
            authenticator_data(flags)?,
            client_data("webauthn.get", V42_CHALLENGE),
        )?;
        verify_v42(&signature)??;
    }
    Ok(())
}

/// Re-signs Vector 42's assertion with `flags` in byte 32 and verifies it.
fn assert_flags_accepted(flags: u8) -> TestResult {
    let signature = resigned(
        authenticator_data(flags)?,
        client_data("webauthn.get", V42_CHALLENGE),
    )?;
    verify_v42(&signature)??;
    Ok(())
}

/// Flags 0x07: reserved bit 1 set beside UP and UV. §9.7.4.2: a verifier
/// "MUST NOT reject … on any other flag bit of byte 32".
#[test]
fn assertion_form_accepts_reserved_bit_1() -> TestResult {
    assert_flags_accepted(0x07)
}

/// Flags 0x25: reserved bit 5 set beside UP and UV.
#[test]
fn assertion_form_accepts_reserved_bit_5() -> TestResult {
    assert_flags_accepted(0x25)
}

/// Flags 0xFF: every bit of byte 32, reserved bits 1 and 5 beside AT, ED,
/// BE, BS, UP and UV.
#[test]
fn assertion_form_accepts_every_flag_bit() -> TestResult {
    assert_flags_accepted(0xFF)
}

/// (h) 36 and (i) 257 bytes of `authenticatorData`, through the constructor
/// and through the wire.
#[test]
fn authenticator_data_bounds_reject() -> TestResult {
    let client_data_json = client_data("webauthn.get", V42_CHALLENGE);
    for len in [36, 257] {
        let mut authenticator = authenticator_data(0x05)?;
        authenticator.resize(len, 0);
        let signature = sign_assertion(&authenticator, &client_data_json)?;
        let expected = IndexedSignatureReadError::AuthenticatorDataLength { len };
        assert_eq!(
            AssertionSignature::new(authenticator.clone(), client_data_json.clone(), signature),
            Err(expected.clone())
        );
        let wire = assertion_wire(&authenticator, &client_data_json, &signature);
        assert_eq!(
            IndexedSignature::read(SignatureForm::WebAuthnAssertion, &wire),
            Err(expected)
        );
    }
    Ok(())
}

/// (j) 0 and (k) 513 bytes of `clientDataJSON`.
#[test]
fn client_data_json_bounds_reject() -> TestResult {
    let authenticator = authenticator_data(0x05)?;
    let mut long = client_data("webauthn.get", V42_CHALLENGE);
    long.resize(513, b' ');
    for client_data_json in [Vec::new(), long] {
        let len = client_data_json.len();
        let signature = sign_assertion(&authenticator, &client_data_json)?;
        let expected = IndexedSignatureReadError::ClientDataJsonLength { len };
        assert_eq!(
            AssertionSignature::new(authenticator.clone(), client_data_json.clone(), signature),
            Err(expected.clone())
        );
        let wire = assertion_wire(&authenticator, &client_data_json, &signature);
        assert_eq!(
            IndexedSignature::read(SignatureForm::WebAuthnAssertion, &wire),
            Err(expected)
        );
    }
    Ok(())
}

/// Boundary accepts: `authenticatorData` of exactly 37 (Vector 42) and 256
/// bytes, `clientDataJSON` of exactly 512 bytes, each read off the wire.
#[test]
fn bounds_accept_at_their_limits() -> TestResult {
    let client_data_json = client_data("webauthn.get", V42_CHALLENGE);
    let mut long_authenticator = authenticator_data(0x05)?;
    long_authenticator.resize(256, 0xA5);
    // Pad the document with an ignored member up to exactly 512 bytes.
    let pad = 512 - client_data_json.len() - r#","pad":"""#.len();
    let mut padded = client_data_json.clone();
    padded.pop();
    padded.extend_from_slice(format!(r#","pad":"{}"}}"#, "x".repeat(pad)).as_bytes());
    assert_eq!(padded.len(), 512);
    for (authenticator, document) in [
        (authenticator_data(0x05)?, client_data_json.clone()),
        (long_authenticator, client_data_json),
        (authenticator_data(0x05)?, padded),
    ] {
        let signature = sign_assertion(&authenticator, &document)?;
        let wire = assertion_wire(&authenticator, &document, &signature);
        let (read, consumed) = IndexedSignature::read(SignatureForm::WebAuthnAssertion, &wire)?;
        assert_eq!(consumed, wire.len());
        verify_v42(&read)??;
    }
    Ok(())
}

/// (l) a declared length, or a fixed-width part, running past the field.
#[test]
fn reads_reject_a_part_running_past_the_field() -> TestResult {
    let field = bytes(V42_INDEXED_SIGNATURE)?;
    let cases = [
        (4 + 10, IndexedSignaturePart::AuthenticatorData),
        (2, IndexedSignaturePart::AuthenticatorDataLength),
        (4 + 37 + 3, IndexedSignaturePart::ClientDataJsonLength),
        (4 + 37 + 4 + 100, IndexedSignaturePart::ClientDataJson),
        (264 - 1, IndexedSignaturePart::AssertionSignature),
    ];
    for (cut, part) in cases {
        let short = field.get(..cut).ok_or("cut")?;
        match IndexedSignature::read(SignatureForm::WebAuthnAssertion, short) {
            Err(IndexedSignatureReadError::Truncated { part: found, .. }) => {
                assert_eq!(found, part);
            }
            other => return Err(format!("cut at {cut}: {other:?}").into()),
        }
    }
    let raw = bytes(V41_SIGNATURE)?;
    assert_eq!(
        IndexedSignature::read(SignatureForm::Raw, raw.get(..63).ok_or("cut")?),
        Err(IndexedSignatureReadError::Truncated {
            part: IndexedSignaturePart::RawSignature,
            remaining: 63
        })
    );
    // A length prefix declaring 0xFFFFFFFF bytes is rejected on its bound
    // before anything is read or sized from it, for each of the two parts.
    let mut huge = field.clone();
    huge.get_mut(..4).ok_or("short")?.fill(0xFF);
    assert_eq!(
        IndexedSignature::read(SignatureForm::WebAuthnAssertion, &huge),
        Err(IndexedSignatureReadError::AuthenticatorDataLength { len: 0xFFFF_FFFF })
    );
    let mut huge = field;
    huge.get_mut(4 + 37..4 + 37 + 4).ok_or("short")?.fill(0xFF);
    assert_eq!(
        IndexedSignature::read(SignatureForm::WebAuthnAssertion, &huge),
        Err(IndexedSignatureReadError::ClientDataJsonLength { len: 0xFFFF_FFFF })
    );
    Ok(())
}

/// A read takes exactly one indexed signature off the front of a field.
#[test]
fn reads_take_one_signature_and_leave_the_rest() -> TestResult {
    let mut field = bytes(V42_INDEXED_SIGNATURE)?;
    field.extend_from_slice(&bytes(V41_SIGNATURE)?);
    let (_, consumed) = IndexedSignature::read(SignatureForm::WebAuthnAssertion, &field)?;
    assert_eq!(consumed, 264);
    let (raw, consumed) =
        IndexedSignature::read(SignatureForm::Raw, field.get(264..).ok_or("short")?)?;
    assert_eq!(consumed, 64);
    verify_indexed(&root()?, &array(V41_DIGEST)?, SignatureForm::Raw, &raw)?;
    Ok(())
}

/// (m) `type` is `"webauthn.create"`.
#[test]
fn assertion_form_rejects_a_create_type() -> TestResult {
    let signature = resigned(
        authenticator_data(0x05)?,
        client_data("webauthn.create", V42_CHALLENGE),
    )?;
    assert_eq!(
        verify_v42(&signature)?,
        Err(IndexedSignatureError::ClientDataTypeMismatch)
    );
    Ok(())
}

/// (n) a challenge over the `"SCP-KEL-EVENT-V1:"` prefix and (o) a
/// challenge over another event's D.
#[test]
fn assertion_form_rejects_a_challenge_for_anything_else() -> TestResult {
    // Unpadded base64url of "SCP-KEL-EVENT-V1:" || Vector 42's D.
    let wrong_prefix = "U0NQLUtFTC1FVkVOVC1WMTqaQbD9uXgBRzCrfY1Wuad3RbT_SCSv_AlrvZI9FKVppg";
    // Unpadded base64url of "SCP-KEY-EVENT-V1:" || Vector 41's D.
    let other_event = "U0NQLUtFWS1FVkVOVC1WMTrYuk661SZXIIc29MrGdTUvX5zAqoN2IPjXQtv0Ku7b1w";
    for challenge in [wrong_prefix, other_event] {
        let signature = resigned(
            authenticator_data(0x05)?,
            client_data("webauthn.get", challenge),
        )?;
        assert_eq!(
            verify_v42(&signature)?,
            Err(IndexedSignatureError::ChallengeMismatch)
        );
    }
    Ok(())
}

/// A challenge carrying `=` padding, or a character outside the base64url
/// alphabet, is rejected. Replacing `_` with `/` gives the standard
/// alphabet's encoding of the same bytes, which a lenient decoder accepts.
#[test]
fn assertion_form_rejects_padding_and_characters_outside_base64url() -> TestResult {
    let padded = format!("{V42_CHALLENGE}=");
    let slash = V42_CHALLENGE.replacen('_', "/", 1);
    let plus = format!("+{}", V42_CHALLENGE.get(1..).ok_or("short")?);
    assert_ne!(slash, V42_CHALLENGE);
    for challenge in [padded, slash, plus] {
        let signature = resigned(
            authenticator_data(0x05)?,
            client_data("webauthn.get", &challenge),
        )?;
        assert_eq!(
            verify_v42(&signature)?,
            Err(IndexedSignatureError::ChallengeMismatch),
            "{challenge}"
        );
    }
    Ok(())
}

/// A challenge whose last character carries nonzero trailing bits names the
/// same bytes under a lenient base64url decoder, and is rejected, because
/// the comparison is string equality with the canonical encoding.
#[test]
fn assertion_form_rejects_a_non_canonical_challenge() -> TestResult {
    let mut challenge = V42_CHALLENGE.to_owned();
    assert_eq!(challenge.pop(), Some('g'));
    challenge.push('h');
    let signature = resigned(
        authenticator_data(0x05)?,
        client_data("webauthn.get", &challenge),
    )?;
    assert_eq!(
        verify_v42(&signature)?,
        Err(IndexedSignatureError::ChallengeMismatch)
    );
    Ok(())
}

/// A `challenge` written with `\u` escapes for the same characters
/// verifies, because the comparison reads the decoded string, never the
/// bytes as written.
#[test]
fn assertion_form_compares_the_decoded_challenge() -> TestResult {
    let escaped_challenge = format!(
        r"\u0055{}\u0067",
        V42_CHALLENGE
            .get(1..V42_CHALLENGE.len() - 1)
            .ok_or("short")?
    );
    let document = format!(
        r#"{{"type":"webauthn.get","challenge":"{escaped_challenge}","origin":"https:\/\/ctx.network"}}"#
    );
    let signature = resigned(authenticator_data(0x05)?, document.into_bytes())?;
    verify_v42(&signature)??;
    Ok(())
}

/// A `type` written with a `\u` escape verifies, for the same reason.
#[test]
fn assertion_form_compares_the_decoded_type() -> TestResult {
    let document = format!(r#"{{"type":"webauthn\u002eget","challenge":"{V42_CHALLENGE}"}}"#);
    let signature = resigned(authenticator_data(0x05)?, document.into_bytes())?;
    verify_v42(&signature)??;
    Ok(())
}

/// (p)–(s) map through `verify_indexed` as `ClientData`: one row shows the
/// mapping, and `client_data.rs` asserts each acceptance-set variant.
#[test]
fn an_acceptance_set_rejection_maps_to_client_data() -> TestResult {
    let signature = resigned(
        authenticator_data(0x05)?,
        format!(r#"{{"challenge":"{V42_CHALLENGE}"}}"#).into_bytes(),
    )?;
    assert_eq!(
        verify_v42(&signature)?,
        Err(IndexedSignatureError::ClientData(
            ClientDataError::MissingType
        ))
    );
    Ok(())
}

/// The PRD case, (v) a duplicate that differs only by an escape, and (w) a
/// challenge only a nested object carries, each re-signed.
#[test]
fn assertion_form_rejects_duplicates_and_nested_challenges() -> TestResult {
    let cases: [(String, ClientDataError); 3] = [
        (
            r#"{"type":"webauthn.get","challenge":"a","challenge":"b"}"#.to_owned(),
            ClientDataError::DuplicateMember { offset: 39 },
        ),
        (
            format!(
                r#"{{"type":"webauthn.get","challenge":"{V42_CHALLENGE}","\u0063hallenge":"{V42_CHALLENGE}"}}"#
            ),
            ClientDataError::DuplicateMember { offset: 104 },
        ),
        (
            format!(r#"{{"type":"webauthn.get","inner":{{"challenge":"{V42_CHALLENGE}"}}}}"#),
            ClientDataError::MissingChallenge,
        ),
    ];
    for (document, error) in cases {
        let signature = resigned(authenticator_data(0x05)?, document.into_bytes())?;
        assert_eq!(
            verify_v42(&signature)?,
            Err(IndexedSignatureError::ClientData(error))
        );
    }
    Ok(())
}

/// Nesting 200 deep inside 512 bytes verifies end to end: no depth limit
/// applies other than the length bound.
#[test]
fn assertion_form_accepts_deep_nesting_within_the_bound() -> TestResult {
    let document = format!(
        r#"{{"type":"webauthn.get","challenge":"{V42_CHALLENGE}","a":{}{}}}"#,
        "[".repeat(200),
        "]".repeat(200)
    );
    assert!(document.len() <= 512, "{} bytes", document.len());
    let signature = resigned(authenticator_data(0x05)?, document.into_bytes())?;
    verify_v42(&signature)??;
    Ok(())
}

/// Vector 42's document with the member Chrome adds to some assertions, a
/// string holding spaces, verifies end to end.
#[test]
fn assertion_form_accepts_chromes_extra_member() -> TestResult {
    let document = format!(
        r#"{{"type":"webauthn.get","challenge":"{V42_CHALLENGE}","origin":"https://ctx.network","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}}"#
    );
    let signature = resigned(authenticator_data(0x05)?, document.into_bytes())?;
    verify_v42(&signature)??;
    Ok(())
}

/// A signature whose form differs from the declared one is rejected before
/// any other check, in both directions.
#[test]
fn a_signature_of_another_form_than_declared_is_rejected() -> TestResult {
    let raw = IndexedSignature::Raw {
        signature: array(V41_SIGNATURE)?,
    };
    assert_eq!(
        verify_indexed(
            &root()?,
            &array(V41_DIGEST)?,
            SignatureForm::WebAuthnAssertion,
            &raw
        ),
        Err(IndexedSignatureError::FormMismatch {
            declared: SignatureForm::WebAuthnAssertion,
            carried: SignatureForm::Raw,
        })
    );
    let (assertion, _) = IndexedSignature::read(
        SignatureForm::WebAuthnAssertion,
        &bytes(V42_INDEXED_SIGNATURE)?,
    )?;
    assert_eq!(
        verify_indexed(&root()?, &v42_digest()?, SignatureForm::Raw, &assertion),
        Err(IndexedSignatureError::FormMismatch {
            declared: SignatureForm::Raw,
            carried: SignatureForm::WebAuthnAssertion,
        })
    );
    Ok(())
}
