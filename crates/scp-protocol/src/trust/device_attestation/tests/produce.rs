//! The owner's pure producer half (`09-security-model.md` §9.3.1, "What the
//! owner's SDK does"), SCP-317 AC2, AC3 and AC5.
//!
//! Every AC3 case runs the owner's whole path through [`publish`]: the
//! response is read, the verdict assembled and checked, and the entry string
//! built only on a pass. A case asserts both the step's typed error and that
//! [`publish`] returns no entry.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use scp_crypto::p256::sign_prehash_rfc6979;
use scp_did::Identifier;
use sha2::{Digest, Sha256};

use super::{
    AppAttestEntryError, AppAttestEntryInput, MAX_VERDICT_REQUEST_LEN, MAX_VERDICT_RESPONSE_LEN,
    MAX_VERDICT_TOKEN_LEN, VERDICT_REFUSED_BODY, VerdictCheck, VerdictCheckInput, VerdictRequest,
    VerdictRequestError, VerdictRequestInput, VerdictResponse, VerdictResponseError,
    app_attest_entry_endpoint, assemble_verdict, check_play_integrity_verdict,
    play_integrity_entry_endpoint, renewal_deadline,
};
use crate::trust::device_attestation::app_attest::{
    APP_ATTEST_CHECKS, APPLE_APP_ATTESTATION_ROOT, AppAttestCheck, AppAttestRead, ClientData, Stop,
    read_app_attest, run as run_app_attest,
};
use crate::trust::device_attestation::cbor::{Value, decode_exact, encode_canonical, lookup};
use crate::trust::device_attestation::digest::device_attestation_tag;
use crate::trust::device_attestation::play_integrity::tests::{
    Identity, NOW, V87_VERDICT, fixture_identifier, verifier_a,
};
use crate::trust::device_attestation::play_integrity::{
    PlayIntegrityRead, PreimageFields, VERDICT_LEN, read_play_integrity,
};
use crate::trust::device_attestation::test_ca::{BoxResult, DAY, TestResult, policy_for};
use crate::trust::device_attestation::{
    DeviceAttestationRejection as R, device_attestation_binding_digest, x509,
};
use crate::trust::sybil::{
    AcceptedAndroidPackage, ApplePlatform, ContextSybilPolicy, MAX_DEVICE_ATTESTATION_MAX_AGE_SECS,
};

// ── Play Integrity fixture ──────────────────────────────────────────────────

const PACKAGE: &str = "com.example.scp";
const CERT: [u8; 32] = [0x83; 32];
const CONTEXT: &str = "ctx-1";
const CHALLENGE: [u8; 32] = [0x11; 32];
const TOKEN: &str = "integrity token A";
const MAX_AGE_SECS: u64 = 30 * DAY;

fn owner() -> Identifier {
    fixture_identifier("the owner")
}

fn policy(verifier: &Identity) -> ContextSybilPolicy {
    let mut policy = ContextSybilPolicy::standard();
    policy.device_attestation_challenge = CHALLENGE;
    policy.device_attestation_max_age_secs = MAX_AGE_SECS;
    policy.accepted_android_packages = vec![AcceptedAndroidPackage {
        package_name: PACKAGE.to_owned(),
        signing_cert_sha256: CERT,
        verifier_identifier: verifier.identifier,
    }];
    policy
}

/// The six response members, which a verifier signs over the owner's
/// identifier, `context_id` and token.
struct Signed {
    verifier: Identifier,
    package_hash: [u8; 32],
    cert_digest: [u8; 32],
    token_issued_at: u64,
    checked_at: u64,
    signature: [u8; 64],
}

impl Signed {
    /// A verdict `verifier` signs over `subject`, `context_id` and `token`.
    fn over(
        verifier: &Identity,
        subject: &Identifier,
        context_id: &str,
        token: &str,
    ) -> BoxResult<Self> {
        Self::at(verifier, subject, context_id, token, NOW - 120, NOW - 60)
    }

    fn at(
        verifier: &Identity,
        subject: &Identifier,
        context_id: &str,
        token: &str,
        token_issued_at: u64,
        checked_at: u64,
    ) -> BoxResult<Self> {
        let binding = device_attestation_binding_digest(subject, context_id, &CHALLENGE)?;
        let package_hash: [u8; 32] = Sha256::digest(PACKAGE).into();
        let fields = PreimageFields {
            verifier: *verifier.identifier.as_bytes(),
            subject: *subject.as_bytes(),
            binding: *binding.as_bytes(),
            token_digest: Sha256::digest(token).into(),
            package_hash,
            cert_digest: CERT,
            token_issued_at,
            checked_at,
        };
        Ok(Self {
            verifier: verifier.identifier,
            package_hash,
            cert_digest: CERT,
            token_issued_at,
            checked_at,
            signature: sign_prehash_rfc6979(&verifier.active, &fields.digest())?,
        })
    }

    /// The six members as `(name, JSON value)`, in JCS order.
    fn members(&self) -> [(&'static str, String); 6] {
        let text = |bytes: &[u8]| format!("\"{}\"", URL_SAFE_NO_PAD.encode(bytes));
        [
            ("cert_digest", text(&self.cert_digest)),
            ("checked_at", self.checked_at.to_string()),
            ("package_hash", text(&self.package_hash)),
            ("signature", text(&self.signature)),
            ("token_issued_at", self.token_issued_at.to_string()),
            ("verifier", format!("\"{}\"", self.verifier)),
        ]
    }

    /// The canonical `200` body.
    fn body(&self) -> Vec<u8> {
        join(&self.members())
    }
}

/// A JSON object of `members` in the order given, with no whitespace.
fn join(members: &[(&str, String)]) -> Vec<u8> {
    let inner: Vec<String> = members
        .iter()
        .map(|(name, value)| format!("\"{name}\":{value}"))
        .collect();
    format!("{{{}}}", inner.join(",")).into_bytes()
}

/// The owner's whole path from the verifier's answer to an entry string:
/// [`VerdictResponse::from_http`], [`assemble_verdict`],
/// [`check_play_integrity_verdict`] and, on a pass only,
/// [`play_integrity_entry_endpoint`]. `None` means nothing is published.
fn publish(
    status: u16,
    body: &[u8],
    policy: &ContextSybilPolicy,
    verifier: &Identity,
    now: u64,
) -> BoxResult<Option<String>> {
    let Ok(response) = VerdictResponse::from_http(status, body) else {
        return Ok(None);
    };
    let verdict = assemble_verdict(&response);
    let key_state = verifier.resolved(now - 10)?;
    let subject = owner();
    let checked = check_play_integrity_verdict(&VerdictCheckInput {
        subject: &subject,
        context_id: CONTEXT,
        policy: policy.validated()?,
        token: TOKEN,
        verdict: &verdict,
        verifiers: &[&key_state],
        now: Duration::from_secs(now),
    })?;
    Ok(match checked {
        VerdictCheck::Passed(checked) => Some(play_integrity_entry_endpoint(&checked)),
        VerdictCheck::Rejected { .. } | VerdictCheck::Unverifiable { .. } => None,
    })
}

/// Asserts the step's error and that the whole path publishes nothing.
fn publishes_nothing(status: u16, body: &[u8], expected: &VerdictResponseError) -> TestResult {
    let a = verifier_a()?;
    assert_eq!(
        VerdictResponse::from_http(status, body).as_ref(),
        Err(expected)
    );
    assert_eq!(publish(status, body, &policy(&a), &a, NOW)?, None);
    Ok(())
}

/// Splits `serviceEndpoint` into its tag and decoded fields.
fn endpoint_fields(endpoint: &str, tag: &str, count: usize) -> BoxResult<Vec<Vec<u8>>> {
    let mut parts = endpoint.split('.');
    assert_eq!(parts.next(), Some(tag));
    let fields = parts
        .map(|field| URL_SAFE_NO_PAD.decode(field))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(fields.len(), count, "{endpoint}");
    Ok(fields)
}

// ── Positive control ────────────────────────────────────────────────────────

/// A canonical `200` whose verdict passes every check publishes
/// `play-integrity.<T>.<token>.<verdict>`, and the reader reads that entry as
/// `Verified`.
#[test]
fn passing_verdict_publishes_entry_the_reader_verifies() -> TestResult {
    let a = verifier_a()?;
    let policy = policy(&a);
    let signed = Signed::over(&a, &owner(), CONTEXT, TOKEN)?;
    let endpoint = publish(200, &signed.body(), &policy, &a, NOW)?
        .ok_or("a passing verdict publishes an entry")?;
    let fields = endpoint_fields(&endpoint, "play-integrity", 3)?;
    let (tag, token, verdict) = (&fields[0], &fields[1], &fields[2]);
    assert_eq!(
        tag.as_slice(),
        device_attestation_tag(&owner(), CONTEXT, &CHALLENGE)?
    );
    assert_eq!(token.as_slice(), TOKEN.as_bytes());
    assert_eq!(verdict.len(), VERDICT_LEN);

    let binding = device_attestation_binding_digest(&owner(), CONTEXT, &CHALLENGE)?;
    let key_state = a.resolved(NOW - 10)?;
    let read = PlayIntegrityRead {
        token,
        verdict,
        binding: &binding,
        policy: policy.validated()?,
        verifiers: &[&key_state],
        now: Duration::from_secs(NOW),
    };
    let verified = read_play_integrity(&read, "entry-0").map_err(|f| format!("{f:?}"))?;
    assert_eq!(verified.minted_at(), NOW - 120);
    Ok(())
}

// ── The verdict request ─────────────────────────────────────────────────────

fn request_input<'a>(
    subject: &'a Identifier,
    policy: &'a ContextSybilPolicy,
    token: &'a str,
) -> BoxResult<VerdictRequestInput<'a>> {
    Ok(VerdictRequestInput {
        subject,
        context_id: CONTEXT,
        policy: policy.validated()?,
        package_name: PACKAGE,
        token,
    })
}

/// The body is the RFC 8785 serialization of the five members, in order.
#[test]
fn request_body_is_canonical_five_members() -> TestResult {
    let a = verifier_a()?;
    let policy = policy(&a);
    let subject = owner();
    let request = VerdictRequest::new(&request_input(&subject, &policy, TOKEN)?)?;
    let expected = format!(
        "{{\"challenge\":\"{}\",\"context_id\":\"{CONTEXT}\",\"package_name\":\"{PACKAGE}\",\"subject\":\"{subject}\",\"token\":\"{TOKEN}\"}}",
        URL_SAFE_NO_PAD.encode(CHALLENGE),
    );
    assert_eq!(request.body(), expected.as_bytes());
    assert_eq!(VerdictRequest::CONTENT_TYPE, "application/json");
    Ok(())
}

/// AC3: a 16,385-byte token builds no request, so nothing is sent and nothing
/// published; a 16,384-byte token builds one.
#[test]
fn token_over_16384_bytes_sends_no_request() -> TestResult {
    let a = verifier_a()?;
    let policy = policy(&a);
    let subject = owner();
    let long = "t".repeat(MAX_VERDICT_TOKEN_LEN + 1);
    assert_eq!(
        VerdictRequest::new(&request_input(&subject, &policy, &long)?),
        Err(VerdictRequestError::TokenTooLong { len: 16_385 })
    );
    let longest = "t".repeat(MAX_VERDICT_TOKEN_LEN);
    VerdictRequest::new(&request_input(&subject, &policy, &longest)?)?;
    Ok(())
}

/// A body of exactly 32,768 bytes is built and one byte more is refused; an
/// unset challenge builds no request. §9.3.1 states no emptiness rule, so an
/// empty member builds a request.
#[test]
fn request_refusals() -> TestResult {
    let a = verifier_a()?;
    let mut policy = policy(&a);
    let subject = owner();
    let mut input = request_input(&subject, &policy, TOKEN)?;
    input.context_id = "";
    let overhead = VerdictRequest::new(&input)?.body().len();
    let fits = "c".repeat(MAX_VERDICT_REQUEST_LEN - overhead);
    input.context_id = &fits;
    assert_eq!(
        VerdictRequest::new(&input)?.body().len(),
        MAX_VERDICT_REQUEST_LEN
    );
    let over = "c".repeat(MAX_VERDICT_REQUEST_LEN - overhead + 1);
    input.context_id = &over;
    assert_eq!(
        VerdictRequest::new(&input),
        Err(VerdictRequestError::BodyTooLong {
            len: MAX_VERDICT_REQUEST_LEN + 1
        })
    );
    for member in ["context_id", "package_name", "token"] {
        let mut input = request_input(&subject, &policy, TOKEN)?;
        match member {
            "context_id" => input.context_id = "",
            "package_name" => input.package_name = "",
            _ => input.token = "",
        }
        VerdictRequest::new(&input)?;
    }
    policy.device_attestation_challenge = [0; 32];
    assert_eq!(
        VerdictRequest::new(&request_input(&subject, &policy, TOKEN)?),
        Err(VerdictRequestError::ChallengeUnset)
    );
    Ok(())
}

// ── AC3: responses that publish nothing ─────────────────────────────────────

#[test]
fn refusal_422_publishes_nothing() -> TestResult {
    publishes_nothing(422, VERDICT_REFUSED_BODY, &VerdictResponseError::Refused)
}

/// A `422` with any other body is not the refusal.
#[test]
fn status_422_other_body_publishes_nothing() -> TestResult {
    publishes_nothing(
        422,
        br#"{"error":"other"}"#,
        &VerdictResponseError::UnexpectedStatus { status: 422 },
    )
}

/// A `500` carrying a verdict that would pass publishes nothing.
#[test]
fn status_500_publishes_nothing() -> TestResult {
    let signed = Signed::over(&verifier_a()?, &owner(), CONTEXT, TOKEN)?;
    publishes_nothing(
        500,
        &signed.body(),
        &VerdictResponseError::UnexpectedStatus { status: 500 },
    )
}

#[test]
fn reordered_members_publishes_nothing() -> TestResult {
    let signed = Signed::over(&verifier_a()?, &owner(), CONTEXT, TOKEN)?;
    let mut members = signed.members();
    members.reverse();
    publishes_nothing(200, &join(&members), &VerdictResponseError::NotCanonical)
}

#[test]
fn extra_whitespace_publishes_nothing() -> TestResult {
    let signed = Signed::over(&verifier_a()?, &owner(), CONTEXT, TOKEN)?;
    let mut body = signed.body();
    body.insert(1, b' ');
    publishes_nothing(200, &body, &VerdictResponseError::NotCanonical)?;
    let mut body = signed.body();
    body.push(b'\n');
    publishes_nothing(200, &body, &VerdictResponseError::NotCanonical)
}

/// A repeated member is refused even when both copies are equal.
///
/// With real ten-digit timestamps every repeated member pushes a body that
/// would otherwise pass past the 358-byte bound, so the bound alone refuses
/// any real repeat; the first case shows that and that nothing is published.
/// The second case shrinks the timestamps to fit the bound, so only the
/// parser can refuse it. Its verdict fails the owner's check anyway, so it
/// asserts only the refusal.
#[test]
fn repeated_member_publishes_nothing() -> TestResult {
    let a = verifier_a()?;
    let signed = Signed::over(&a, &owner(), CONTEXT, TOKEN)?;
    let mut members = signed.members().to_vec();
    members.push(members[5].clone());
    let body = join(&members);
    assert_eq!(
        VerdictResponse::from_http(200, &body),
        Err(VerdictResponseError::BodyTooLong { len: body.len() })
    );
    assert_eq!(publish(200, &body, &policy(&a), &a, NOW)?, None);
    // With one-digit timestamps a repeated `checked_at` fits the bound, and
    // the parser refuses it.
    let mut short = Signed::over(&a, &owner(), CONTEXT, TOKEN)?;
    short.token_issued_at = 1;
    short.checked_at = 2;
    let mut members = short.members().to_vec();
    members.push(members[1].clone());
    let body = join(&members);
    assert!(body.len() <= MAX_VERDICT_RESPONSE_LEN);
    assert!(VerdictResponse::from_http(200, &body).is_err());
    Ok(())
}

#[test]
fn extra_member_publishes_nothing() -> TestResult {
    let signed = Signed::over(&verifier_a()?, &owner(), CONTEXT, TOKEN)?;
    let mut members = signed.members().to_vec();
    members.push(("zz", "1".to_owned()));
    let body = join(&members);
    let a = verifier_a()?;
    assert!(VerdictResponse::from_http(200, &body).is_err());
    assert_eq!(publish(200, &body, &policy(&a), &a, NOW)?, None);
    Ok(())
}

/// AC3: a canonical `200` whose verdict fails check 6 (signed over another
/// context) publishes nothing; the owner's check returns the reader's cause.
#[test]
fn signed_verdict_failing_check_6_publishes_nothing() -> TestResult {
    let a = verifier_a()?;
    let policy = policy(&a);
    let signed = Signed::over(&a, &owner(), "another context", TOKEN)?;
    let response = VerdictResponse::from_http(200, &signed.body())?;
    let verdict = assemble_verdict(&response);
    let key_state = a.resolved(NOW - 10)?;
    let subject = owner();
    assert_eq!(
        check_play_integrity_verdict(&VerdictCheckInput {
            subject: &subject,
            context_id: CONTEXT,
            policy: policy.validated()?,
            token: TOKEN,
            verdict: &verdict,
            verifiers: &[&key_state],
            now: Duration::from_secs(NOW),
        })?,
        VerdictCheck::Rejected {
            cause: R::VerdictSignatureInvalid
        }
    );
    assert_eq!(publish(200, &signed.body(), &policy, &a, NOW)?, None);
    Ok(())
}

/// An unset challenge fails the owner's check as procedure step 1 does.
#[test]
fn unset_challenge_check_rejected() -> TestResult {
    let a = verifier_a()?;
    let mut policy = policy(&a);
    let signed = Signed::over(&a, &owner(), CONTEXT, TOKEN)?;
    policy.device_attestation_challenge = [0; 32];
    let verdict = assemble_verdict(&VerdictResponse::from_http(200, &signed.body())?);
    let subject = owner();
    assert_eq!(
        check_play_integrity_verdict(&VerdictCheckInput {
            subject: &subject,
            context_id: CONTEXT,
            policy: policy.validated()?,
            token: TOKEN,
            verdict: &verdict,
            verifiers: &[],
            now: Duration::from_secs(NOW),
        })?,
        VerdictCheck::Rejected {
            cause: R::ContextChallengeUnset
        }
    );
    Ok(())
}

// ── The response members ────────────────────────────────────────────────────

/// The base64url alphabet, in value order.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A member whose string is not the canonical encoding of its length is
/// refused: nonzero trailing bits, a short value, and an uppercase verifier.
#[test]
fn noncanonical_member_publishes_nothing() -> TestResult {
    let signed = Signed::over(&verifier_a()?, &owner(), CONTEXT, TOKEN)?;
    let canonical = URL_SAFE_NO_PAD.encode(signed.package_hash);
    let mut trailing = canonical.into_bytes();
    // The 43rd character holds the last 4 bits and 2 trailing zero bits; the
    // next character of the alphabet sets the lowest trailing bit and decodes
    // to the same 32 bytes.
    let last = trailing.len() - 1;
    let index = ALPHABET
        .iter()
        .position(|symbol| *symbol == trailing[last])
        .ok_or("base64url symbol")?;
    assert_eq!(index & 0b11, 0, "canonical trailing bits are zero");
    trailing[last] = ALPHABET[index | 1];
    let cases: [(usize, String, &str); 4] = [
        (
            2,
            format!("\"{}\"", String::from_utf8(trailing)?),
            "package_hash",
        ),
        (
            0,
            format!("\"{}\"", URL_SAFE_NO_PAD.encode([0u8; 31])),
            "cert_digest",
        ),
        (
            3,
            format!("\"{}\"", URL_SAFE_NO_PAD.encode([0u8; 65])),
            "signature",
        ),
        (
            5,
            format!("\"{}\"", signed.verifier.to_string().to_uppercase()),
            "verifier",
        ),
    ];
    for (index, value, member) in cases {
        let mut members = signed.members();
        members[index].1 = value;
        publishes_nothing(
            200,
            &join(&members),
            &VerdictResponseError::MemberNotCanonical { member },
        )?;
    }
    Ok(())
}

/// The longest canonical body (both timestamps at 2^53) is read; a body one
/// byte longer is refused before it is parsed.
#[test]
fn response_length_bound() -> TestResult {
    let mut signed = Signed::over(&verifier_a()?, &owner(), CONTEXT, TOKEN)?;
    signed.token_issued_at = 1 << 53;
    signed.checked_at = 1 << 53;
    let body = signed.body();
    assert_eq!(body.len(), MAX_VERDICT_RESPONSE_LEN);
    VerdictResponse::from_http(200, &body)?;
    let mut longer = body;
    longer.push(b' ');
    assert_eq!(
        VerdictResponse::from_http(200, &longer),
        Err(VerdictResponseError::BodyTooLong { len: 359 })
    );
    Ok(())
}

/// A timestamp past 2^53 has no exact JCS form.
#[test]
fn timestamp_past_2_pow_53_refused() -> TestResult {
    let mut signed = Signed::over(&verifier_a()?, &owner(), CONTEXT, TOKEN)?;
    signed.checked_at = (1 << 53) + 1;
    assert_eq!(
        VerdictResponse::from_http(200, &signed.body()),
        Err(VerdictResponseError::NotCanonical)
    );
    Ok(())
}

/// The assembled verdict is spec 25 §25.35 Vector 87's 176 bytes when the
/// response carries Vector 87's members.
#[test]
fn assemble_verdict_matches_vector_87() -> TestResult {
    let expected = hex::decode(V87_VERDICT)?;
    let field = |range: std::ops::Range<usize>| expected.get(range).unwrap_or_default();
    let be64 = |range| -> BoxResult<u64> { Ok(u64::from_be_bytes(field(range).try_into()?)) };
    let verifier = Identifier::from_bytes(field(0..32).try_into()?);
    let members = [
        (
            "cert_digest",
            format!("\"{}\"", URL_SAFE_NO_PAD.encode(field(64..96))),
        ),
        ("checked_at", be64(104..112)?.to_string()),
        (
            "package_hash",
            format!("\"{}\"", URL_SAFE_NO_PAD.encode(field(32..64))),
        ),
        (
            "signature",
            format!("\"{}\"", URL_SAFE_NO_PAD.encode(field(112..176))),
        ),
        ("token_issued_at", be64(96..104)?.to_string()),
        ("verifier", format!("\"{verifier}\"")),
    ];
    let response = VerdictResponse::from_http(200, &join(&members))?;
    assert_eq!(response.verifier(), &verifier);
    assert_eq!(assemble_verdict(&response).as_slice(), expected.as_slice());
    Ok(())
}

// ── AC5: renewal ────────────────────────────────────────────────────────────

/// AC5: the renewal deadline is `minted_at + device_attestation_max_age_secs`,
/// saturating at `u64::MAX`, and it is the last second the owner's check (the
/// reader's checks) passes the entry.
#[test]
fn renew_before_deadline_saturating() -> TestResult {
    let a = verifier_a()?;
    let policy = policy(&a);
    let validated = policy.validated()?;
    assert_eq!(renewal_deadline(&validated, u64::MAX - 10), u64::MAX);
    assert_eq!(renewal_deadline(&validated, u64::MAX), u64::MAX);
    let minted_at = NOW - 120;
    let deadline = renewal_deadline(&validated, minted_at);
    assert_eq!(deadline, minted_at + MAX_AGE_SECS);

    let signed = Signed::over(&a, &owner(), CONTEXT, TOKEN)?;
    assert!(publish(200, &signed.body(), &policy, &a, deadline)?.is_some());
    assert_eq!(
        publish(200, &signed.body(), &policy, &a, deadline + 1)?,
        None
    );
    Ok(())
}

// ── AC2: the App Attest object ──────────────────────────────────────────────

/// Apple's production sample (`app_attest/samples/go-prod.cbor`), which
/// verifies under the pinned root.
const GO_PROD: &[u8] = include_bytes!("../app_attest/samples/go-prod.cbor");
const GO_PROD_APP_ID: &str = "0352187391.com.apple.example_app_attest";

fn encode(value: &Value) -> BoxResult<Vec<u8>> {
    let mut out = Vec::new();
    encode_canonical(value, &mut out).map_err(|_| "encodes")?;
    Ok(out)
}

fn top_level(object: &[u8]) -> BoxResult<Vec<(Value, Value)>> {
    match decode_exact(object).map_err(|_| "decodes")? {
        Value::Map(pairs) => Ok(pairs),
        other => Err(format!("expected a map, got {other:?}").into()),
    }
}

fn member<'v>(pairs: &'v [(Value, Value)], key: &str) -> BoxResult<&'v Value> {
    lookup(pairs, key)
        .map_err(|_| "repeated key")?
        .ok_or_else(|| format!("no {key}").into())
}

/// The sample with a long-form map head, its keys out of canonical order and
/// one extra key.
fn noncanonical_sample() -> BoxResult<Vec<u8>> {
    let pairs = top_level(GO_PROD)?;
    let mut out = vec![0xb9];
    out.extend_from_slice(&u16::try_from(pairs.len() + 1)?.to_be_bytes());
    for (key, value) in pairs.iter().rev() {
        out.extend(encode(key)?);
        out.extend(encode(value)?);
    }
    out.extend(encode(&Value::Text("extra".to_owned()))?);
    out.extend(encode(&Value::Unsigned(7))?);
    Ok(out)
}

fn leaf_not_before(object: &[u8]) -> BoxResult<u64> {
    let pairs = top_level(object)?;
    let Value::Map(statement) = member(&pairs, "attStmt")? else {
        return Err("attStmt is a map".into());
    };
    let Value::Array(chain) = member(statement, "x5c")? else {
        return Err("x5c is an array".into());
    };
    let Some(Value::Bytes(leaf)) = chain.first() else {
        return Err("x5c holds the leaf".into());
    };
    Ok(x509::parse_tbs(x509::split_certificate(leaf)?.tbs)?.not_before)
}

fn sample_policy() -> ContextSybilPolicy {
    let mut policy = policy_for(ApplePlatform::Ios);
    policy.device_attestation_max_age_secs = MAX_DEVICE_ATTESTATION_MAX_AGE_SECS;
    if let Some(accepted) = policy.accepted_app_ids.first_mut() {
        accepted.app_id = GO_PROD_APP_ID.to_owned();
    }
    policy
}

/// The attestation object of the entry the owner builds from `object`.
fn published_object(object: &[u8], policy: &ContextSybilPolicy) -> BoxResult<Vec<u8>> {
    let subject = owner();
    let endpoint = app_attest_entry_endpoint(&AppAttestEntryInput {
        subject: &subject,
        context_id: CONTEXT,
        policy: policy.validated()?,
        attestation_object: object,
    })?;
    let fields = endpoint_fields(&endpoint, "app-attest", 2)?;
    assert_eq!(
        fields[0].as_slice(),
        device_attestation_tag(&subject, CONTEXT, &policy.device_attestation_challenge)?
    );
    Ok(fields[1].clone())
}

/// AC2: Apple's sample re-encoded with a long-form length, reordered keys and
/// an extra key fails checks 1 and 2 as given; the object the owner publishes
/// passes both, and the full reader with the owner's `D` stops at exactly
/// `NonceMismatch`, because Apple's nonce covers the sample's own client data.
#[test]
fn noncanonical_apple_object_canonicalized_passes_reader_encoding_checks() -> TestResult {
    let policy = sample_policy();
    let noncanonical = noncanonical_sample()?;
    let binding =
        device_attestation_binding_digest(&owner(), CONTEXT, &policy.device_attestation_challenge)?;
    let now_secs = leaf_not_before(GO_PROD)? + 60;
    let read = |object| -> BoxResult<AppAttestRead<'_>> {
        Ok(AppAttestRead {
            attestation_object: object,
            client_data: ClientData::from(&binding),
            policy: policy.validated()?,
            now_secs,
            entry_id: "entry-0",
        })
    };
    let encoding_checks = APP_ATTEST_CHECKS.get(..2).ok_or("checks 1 and 2")?;

    let before = run_app_attest(
        &APPLE_APP_ATTESTATION_ROOT,
        &read(&noncanonical)?,
        encoding_checks,
    );
    assert_eq!(before.result, Err(Stop::Reject(R::MalformedToken)));

    let published = published_object(&noncanonical, &policy)?;
    let after = run_app_attest(
        &APPLE_APP_ATTESTATION_ROOT,
        &read(&published)?,
        encoding_checks,
    );
    assert!(after.result.is_ok(), "{:?}", after.result);
    assert_eq!(
        after.ran,
        [AppAttestCheck::ObjectEncoding, AppAttestCheck::AuthData]
    );
    assert_eq!(read_app_attest(&read(&published)?), Err(R::NonceMismatch));
    Ok(())
}

fn text_keys(pairs: &[(Value, Value)]) -> Vec<&str> {
    pairs
        .iter()
        .filter_map(|(key, _)| match key {
            Value::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn statement(pairs: &[(Value, Value)]) -> BoxResult<&[(Value, Value)]> {
    match member(pairs, "attStmt")? {
        Value::Map(statement) => Ok(statement),
        other => Err(format!("attStmt is {other:?}").into()),
    }
}

/// AC2: the published object holds `fmt`, `attStmt.x5c` and `authData` only;
/// Apple's `attStmt.receipt` and the extra key are gone, and `fmt`, the chain
/// and `authData` are Apple's bytes.
#[test]
fn receipt_stripped_and_auth_data_bytes_unchanged() -> TestResult {
    let original = top_level(GO_PROD)?;
    assert!(
        text_keys(statement(&original)?).contains(&"receipt"),
        "the sample carries a receipt"
    );
    let published = top_level(&published_object(
        &noncanonical_sample()?,
        &sample_policy(),
    )?)?;
    assert_eq!(text_keys(&published), ["fmt", "attStmt", "authData"]);
    assert_eq!(text_keys(statement(&published)?), ["x5c"]);
    for key in ["fmt", "authData"] {
        assert_eq!(member(&published, key)?, member(&original, key)?, "{key}");
    }
    assert_eq!(
        member(statement(&published)?, "x5c")?,
        member(statement(&original)?, "x5c")?
    );
    Ok(())
}

/// No App Attest entry is built for an unset challenge or an object that is
/// not an App Attest object.
#[test]
fn app_attest_entry_refusals() -> TestResult {
    let subject = owner();
    let policy = sample_policy();
    assert!(matches!(
        app_attest_entry_endpoint(&AppAttestEntryInput {
            subject: &subject,
            context_id: CONTEXT,
            policy: policy.validated()?,
            attestation_object: &[0xa0],
        }),
        Err(AppAttestEntryError::Object(_))
    ));
    let mut unset = sample_policy();
    unset.device_attestation_challenge = [0; 32];
    assert_eq!(
        app_attest_entry_endpoint(&AppAttestEntryInput {
            subject: &subject,
            context_id: CONTEXT,
            policy: unset.validated()?,
            attestation_object: GO_PROD,
        }),
        Err(AppAttestEntryError::ChallengeUnset)
    );
    Ok(())
}
