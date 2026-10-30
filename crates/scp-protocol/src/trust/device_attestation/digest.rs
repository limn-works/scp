//! The four device-attestation digests of `09-security-model.md` §9.3.1.
//!
//! - `D`, the binding digest a platform request carries.
//! - `T`, the tag an entry publishes in place of the challenge.
//! - `A`, the assertion digest the adapter's assertion path passes.
//! - `P`, the policy digest a reader's cache key holds.
//!
//! §25.35 Vectors 84 through 86 pin each preimage and digest.

use sha2::{Digest, Sha256};

use scp_did::Identifier;

use crate::crypto::canonical::{CanonicalError, CanonicalField, MAX_VAR_BYTES_LEN};
use crate::trust::sybil::{ApplePlatform, ValidatedSybilPolicy};

/// Separator of the binding digest `D` (§9.18.2).
const BINDING_SEPARATOR: &[u8] = b"SCP-DEVICE-ATTESTATION-V1:";
/// Separator of the tag `T` (§9.18.2).
const TAG_SEPARATOR: &[u8] = b"SCP-DEVICE-ATTESTATION-TAG-V1:";
/// Separator of the assertion digest `A` (§9.18.2).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
const ASSERTION_SEPARATOR: &[u8] = b"SCP-DEVICE-ASSERTION-V1:";
/// Separator of the policy digest `P` (§9.18.2).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
const POLICY_SEPARATOR: &[u8] = b"SCP-DEVICE-ATTESTATION-POLICY-V1:";

/// The `D` and `T` preimage after its separator: `BE32(56) || identifier_text
/// || BE32(n) || context_id || challenge`.
fn binding_preimage(
    separator: &[u8],
    identifier: &Identifier,
    context_id: &str,
    challenge: &[u8; 32],
) -> Result<Vec<u8>, CanonicalError> {
    let identifier_text = identifier.to_string();
    crate::crypto::canonical::canonical_hash_bytes(
        separator,
        &[
            CanonicalField::VarBytes(identifier_text.as_bytes()),
            CanonicalField::VarBytes(context_id.as_bytes()),
            CanonicalField::Fixed32(challenge),
        ],
    )
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
fn assertion_preimage(request: &[u8]) -> Result<Vec<u8>, CanonicalError> {
    crate::crypto::canonical::canonical_hash_bytes(
        ASSERTION_SEPARATOR,
        &[CanonicalField::VarBytes(request)],
    )
}

/// `BE32(len) || bytes`, under §9.5.1's variable-length rule.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
fn put_var(preimage: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CanonicalError> {
    put_count(preimage, bytes.len())?;
    preimage.extend_from_slice(bytes);
    Ok(())
}

/// A list's `BE32(count)` prefix, or a length prefix.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
fn put_count(preimage: &mut Vec<u8>, count: usize) -> Result<(), CanonicalError> {
    let count = u32::try_from(count).map_err(|_| CanonicalError::FieldTooLarge {
        size: count,
        max: MAX_VAR_BYTES_LEN,
    })?;
    preimage.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
const fn platform_byte(platform: ApplePlatform) -> u8 {
    match platform {
        ApplePlatform::Ios => 0x00,
        ApplePlatform::MacOs => 0x01,
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
fn policy_preimage(policy: ValidatedSybilPolicy<'_>) -> Result<Vec<u8>, CanonicalError> {
    let policy = policy.policy();
    let mut preimage = Vec::with_capacity(256);
    preimage.extend_from_slice(POLICY_SEPARATOR);
    preimage.extend_from_slice(&policy.device_attestation_challenge);
    preimage.extend_from_slice(&policy.device_attestation_max_age_secs.to_be_bytes());
    put_count(&mut preimage, policy.accepted_app_ids.len())?;
    for accepted in &policy.accepted_app_ids {
        put_var(&mut preimage, accepted.app_id.as_bytes())?;
        preimage.push(platform_byte(accepted.platform));
        put_count(&mut preimage, accepted.accepted_bundle_versions.len())?;
        for version in &accepted.accepted_bundle_versions {
            put_var(&mut preimage, version.as_bytes())?;
        }
    }
    put_count(&mut preimage, policy.accepted_validation_categories.len())?;
    for category in &policy.accepted_validation_categories {
        preimage.extend_from_slice(&category.to_be_bytes());
    }
    preimage.push(u8::from(policy.require_validation_category));
    put_count(&mut preimage, policy.accepted_android_packages.len())?;
    for package in &policy.accepted_android_packages {
        put_var(&mut preimage, package.package_name.as_bytes())?;
        preimage.extend_from_slice(&package.signing_cert_sha256);
        preimage.extend_from_slice(package.verifier_identifier.as_bytes());
    }
    Ok(preimage)
}

/// A binding digest `D` (§9.3.1), which only
/// [`device_attestation_binding_digest`] builds, with the identifier it
/// covers.
///
/// The App Attest and Play Integrity checks take a `BindingDigest`, never raw
/// bytes, so no caller can have an attestation verified against a `D` it
/// chose: the digest always covers an identifier, a context id and a
/// challenge. Play Integrity check 6 reads the verdict preimage's `subject`
/// from the same value, so no caller can pair one identifier's `D` with
/// another subject. The fields are private, so code outside this module
/// cannot build one.
///
/// ```compile_fail,E0451
/// let forged = scp_protocol::trust::device_attestation::digest::BindingDigest {
///     digest: [0; 32],
///     subject: scp_did::Identifier::ZERO,
/// };
/// ```
///
/// The positive control: the type and its accessor are public, so the
/// literal above fails on the private fields alone.
///
/// ```
/// use scp_protocol::trust::device_attestation::digest::BindingDigest;
/// fn bytes(d: &BindingDigest) -> [u8; 32] {
///     *d.as_bytes()
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingDigest {
    digest: [u8; 32],
    subject: Identifier,
}

impl BindingDigest {
    /// The digest's 32 bytes: the App Attest `clientDataHash`, and in
    /// lowercase hexadecimal the Play Integrity `requestHash`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The identifier the digest covers: the subject of a Play Integrity
    /// verdict preimage (§9.3.1 Play Integrity check 6).
    pub(crate) const fn subject(&self) -> &Identifier {
        &self.subject
    }
}

/// The binding digest `D` (§9.3.1) over the identifier, the context and the
/// challenge.
///
/// It is the `clientDataHash` of an App Attest attestation, and in lowercase
/// hexadecimal the `requestHash` of a Play Integrity request.
///
/// # Errors
///
/// [`CanonicalError::FieldTooLarge`] when `context_id` exceeds `u32::MAX`
/// bytes.
pub fn device_attestation_binding_digest(
    identifier: &Identifier,
    context_id: &str,
    challenge: &[u8; 32],
) -> Result<BindingDigest, CanonicalError> {
    let preimage = binding_preimage(BINDING_SEPARATOR, identifier, context_id, challenge)?;
    Ok(BindingDigest {
        digest: Sha256::digest(preimage).into(),
        subject: *identifier,
    })
}

/// The tag `T` (§9.3.1) an entry publishes in place of the challenge. It
/// differs for every identifier and every context, so a party without the
/// challenge cannot tell which context an entry serves.
///
/// # Errors
///
/// [`CanonicalError::FieldTooLarge`] when `context_id` exceeds `u32::MAX`
/// bytes.
pub(crate) fn device_attestation_tag(
    identifier: &Identifier,
    context_id: &str,
    challenge: &[u8; 32],
) -> Result<[u8; 32], CanonicalError> {
    let preimage = binding_preimage(TAG_SEPARATOR, identifier, context_id, challenge)?;
    Ok(Sha256::digest(preimage).into())
}

/// The assertion digest `A` (§9.3.1) over the caller's request bytes `m`. A
/// platform assertion carries `A`, never `m`, so no assertion's request hash
/// equals any `D`.
///
/// # Errors
///
/// [`CanonicalError::FieldTooLarge`] when `request` exceeds `u32::MAX` bytes.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
pub(crate) fn device_assertion_digest(request: &[u8]) -> Result<[u8; 32], CanonicalError> {
    let preimage = assertion_preimage(request)?;
    Ok(Sha256::digest(preimage).into())
}

/// The policy digest `P` (§9.3.1), one of the four values a reader's cache key
/// holds. It covers the challenge, so a governance change of the challenge
/// drops every cached outcome for the context.
///
/// # Errors
///
/// [`CanonicalError::FieldTooLarge`] when a list holds more than `u32::MAX`
/// elements or a string exceeds `u32::MAX` bytes.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
pub(crate) fn policy_digest(policy: ValidatedSybilPolicy<'_>) -> Result<[u8; 32], CanonicalError> {
    let preimage = policy_preimage(policy)?;
    Ok(Sha256::digest(preimage).into())
}

#[cfg(test)]
mod tests {
    //! Each pin compares against the §25.35 literal the generator
    //! `scripts/gen-test-vectors-p256.py` prints, which shares no code with
    //! this module.

    use sha2::{Digest, Sha256};

    use scp_did::Identifier;

    use super::{
        ASSERTION_SEPARATOR, BINDING_SEPARATOR, TAG_SEPARATOR, assertion_preimage,
        binding_preimage, device_assertion_digest, device_attestation_binding_digest,
        device_attestation_tag, policy_digest, policy_preimage,
    };
    use crate::trust::sybil::{
        AcceptedAndroidPackage, AcceptedAppId, ApplePlatform, ContextSybilPolicy,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// §25.35: the subject text form.
    const SUBJECT_TEXT: &str = "scp:ktarg6aqtsju6mh2ws3hk7t5kmsvmckq7d5eqwsmaw5di3e3p4ta";
    /// §25.35 Vector 84a.
    const D_PREIMAGE_HEX: &str = concat!(
        "5343502d4445564943452d4154544553544154494f4e2d56313a000000387363",
        "703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d63",
        "6b71376435657177736d617735646933653370347461000000056374782d3120",
        "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    );
    const D_HEX: &str = "66318c86819e17ad71427eabe4cf46590f16adb2bed9e43c9c7dc18ea060bbd3";
    /// §25.35 Vector 84b.
    const T_PREIMAGE_HEX: &str = concat!(
        "5343502d4445564943452d4154544553544154494f4e2d5441472d56313a0000",
        "00387363703a6b7461726736617174736a75366d6832777333686b3774356b6d",
        "73766d636b71376435657177736d617735646933653370347461000000056374",
        "782d31202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c",
        "3d3e3f",
    );
    const T_HEX: &str = "4d462ead28cfe33b7cee1d01fd9da538e984858260227fcfd3d53c2b4c27d550";
    const T_BASE64URL: &str = "TUYurSjP4zt87h0B_Z2lOOmEhYJgIn_P09U8K0wn1VA";
    /// §25.35 Vector 85.
    const A_PREIMAGE_HEX: &str = concat!(
        "5343502d4445564943452d415353455254494f4e2d56313a0000002153435020",
        "7465737420766563746f7220617373657274696f6e2072657175657374",
    );
    const A_HEX: &str = "678ab334973418b55ed733637a81b24c6e9d37bc4ea89df227cecf9c3ebedc35";
    /// §25.35 Vector 86.
    const SIGNING_CERT_HEX: &str =
        "83599d12bbbeff09725d9d6ea2222acadb684c092b9f534dbaf10f973f6f5bd0";
    const P_PREIMAGE_HEX: &str = concat!(
        "5343502d4445564943452d4154544553544154494f4e2d504f4c4943592d5631",
        "3a202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e",
        "3f0000000000278d00000000010000001a414243444531323334352e636f6d2e",
        "6578616d706c652e736370000000000100000003312e30000000010000000401",
        "000000010000000f636f6d2e6578616d706c652e73637083599d12bbbeff0972",
        "5d9d6ea2222acadb684c092b9f534dbaf10f973f6f5bd0aca2c93825d53244c8",
        "23000db9dec0a02498bdb3ed96aa2ce038425b4c65001e",
    );
    const P_HEX: &str = "8bb83191f4f322501d2cd65070a4f61b438887934aaea29f1797f974d5fe19ef";

    fn fixture_identifier(label: &str) -> Identifier {
        Identifier::from_bytes(Sha256::digest(label.as_bytes()).into())
    }

    fn subject() -> Identifier {
        fixture_identifier("SCP test vector identifier subject")
    }

    /// The bytes 20 through 3f.
    fn challenge() -> [u8; 32] {
        let mut challenge = [0u8; 32];
        for (byte, value) in challenge.iter_mut().zip(0x20u8..) {
            *byte = value;
        }
        challenge
    }

    fn vector_86_policy() -> ContextSybilPolicy {
        let signing_cert_sha256: [u8; 32] =
            Sha256::digest(b"SCP test vector signing certificate").into();
        assert_eq!(hex::encode(signing_cert_sha256), SIGNING_CERT_HEX);
        ContextSybilPolicy {
            device_attestation_challenge: challenge(),
            device_attestation_max_age_secs: 2_592_000,
            accepted_app_ids: vec![AcceptedAppId {
                app_id: "ABCDE12345.com.example.scp".to_owned(),
                platform: ApplePlatform::Ios,
                accepted_bundle_versions: vec!["1.0".to_owned()],
            }],
            accepted_validation_categories: vec![4],
            require_validation_category: true,
            accepted_android_packages: vec![AcceptedAndroidPackage {
                package_name: "com.example.scp".to_owned(),
                signing_cert_sha256,
                verifier_identifier: fixture_identifier("SCP test vector identifier verifier"),
            }],
            ..ContextSybilPolicy::casual()
        }
    }

    /// §25.35 Vector 84a: the 127-byte preimage (`122 + n`, `n` = 5) and `D`.
    /// Must fail: one changed byte of the context id changes `D`.
    #[test]
    fn binding_digest_preimage_pins_122_plus_n() -> TestResult {
        assert_eq!(subject().to_string(), SUBJECT_TEXT);
        let preimage = binding_preimage(BINDING_SEPARATOR, &subject(), "ctx-1", &challenge())?;
        assert_eq!(preimage.len(), 122 + 5);
        assert_eq!(hex::encode(&preimage), D_PREIMAGE_HEX);
        let d = device_attestation_binding_digest(&subject(), "ctx-1", &challenge())?;
        assert_eq!(hex::encode(d.as_bytes()), D_HEX);
        let other = device_attestation_binding_digest(&subject(), "ctx-2", &challenge())?;
        assert_ne!(hex::encode(other.as_bytes()), D_HEX);
        Ok(())
    }

    /// §25.35 Vector 84b: the 131-byte preimage (`126 + n`), `T`, and its
    /// unpadded base64url form.
    #[test]
    fn tag_preimage_pins_126_plus_n() -> TestResult {
        use base64::Engine as _;
        let preimage = binding_preimage(TAG_SEPARATOR, &subject(), "ctx-1", &challenge())?;
        assert_eq!(preimage.len(), 126 + 5);
        assert_eq!(hex::encode(&preimage), T_PREIMAGE_HEX);
        let t = device_attestation_tag(&subject(), "ctx-1", &challenge())?;
        assert_eq!(hex::encode(t), T_HEX);
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(t),
            T_BASE64URL
        );
        Ok(())
    }

    /// Two contexts sharing one challenge give one identity two tags, and no
    /// tag equals its binding digest.
    #[test]
    fn tag_differs_across_contexts_sharing_challenge() -> TestResult {
        let first = device_attestation_tag(&subject(), "ctx-1", &challenge())?;
        let second = device_attestation_tag(&subject(), "ctx-2", &challenge())?;
        assert_ne!(first, second);
        let other_identity =
            device_attestation_tag(&fixture_identifier("another"), "ctx-1", &challenge())?;
        assert_ne!(first, other_identity);
        assert_ne!(
            first,
            *device_attestation_binding_digest(&subject(), "ctx-1", &challenge())?.as_bytes()
        );
        Ok(())
    }

    /// The separator alone keeps `A` from equalling a digest under `D`'s
    /// separator: for an `m` equal to the `D` preimage after its separator,
    /// `A`'s preimage after its separator is copied behind `D`'s separator, so
    /// the two preimages differ only in the separator, and the two digests
    /// must differ. The check runs before the §25.35 Vector 85 pins, so making
    /// `A`'s separator equal to `D`'s fails at this `assert_ne!` and not at a
    /// pin.
    #[test]
    fn assertion_digest_differs_from_binding_digest_on_equal_concatenation() -> TestResult {
        let d_preimage = binding_preimage(BINDING_SEPARATOR, &subject(), "ctx-1", &challenge())?;
        let m = d_preimage
            .get(BINDING_SEPARATOR.len()..)
            .ok_or("the D preimage is shorter than its separator")?;
        let a_preimage = assertion_preimage(m)?;
        let a_body = a_preimage
            .get(ASSERTION_SEPARATOR.len()..)
            .ok_or("the A preimage is shorter than its separator")?;
        let under_d_separator = [BINDING_SEPARATOR, a_body].concat();
        let a = device_assertion_digest(m)?;
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&a_preimage)), a);
        assert_ne!(
            a,
            <[u8; 32]>::from(Sha256::digest(&under_d_separator)),
            "A over m must differ from a digest of the same bytes under D's separator"
        );
        assert_ne!(hex::encode(a), D_HEX);

        let request = b"SCP test vector assertion request";
        let preimage = assertion_preimage(request)?;
        assert_eq!(preimage.len(), 24 + 4 + 33);
        assert_eq!(hex::encode(&preimage), A_PREIMAGE_HEX);
        assert_eq!(hex::encode(device_assertion_digest(request)?), A_HEX);
        Ok(())
    }

    /// §25.35 Vector 86: the 215-byte preimage and `P`. Must fail: flipping
    /// `require_validation_category` changes `P`.
    #[test]
    fn policy_digest_preimage_pins() -> TestResult {
        let policy = vector_86_policy();
        let validated = policy.validated()?;
        let preimage = policy_preimage(validated)?;
        assert_eq!(preimage.len(), 215);
        assert_eq!(hex::encode(&preimage), P_PREIMAGE_HEX);
        assert_eq!(hex::encode(policy_digest(validated)?), P_HEX);

        let flipped = ContextSybilPolicy {
            require_validation_category: false,
            ..vector_86_policy()
        };
        assert_ne!(hex::encode(policy_digest(flipped.validated()?)?), P_HEX);
        Ok(())
    }

    /// Each element of `P` that §9.3.1 names moves the digest: the platform
    /// byte, the bundle-version list, the category list and the verifier.
    #[test]
    fn policy_digest_covers_every_field() -> TestResult {
        let base = vector_86_policy();
        let pinned = policy_digest(base.validated()?)?;
        let mut variants = Vec::new();
        let mut macos = base.clone();
        if let Some(first) = macos.accepted_app_ids.first_mut() {
            first.platform = ApplePlatform::MacOs;
        }
        variants.push(macos);
        let mut versions = base.clone();
        if let Some(first) = versions.accepted_app_ids.first_mut() {
            first.accepted_bundle_versions.push("1.1".to_owned());
        }
        variants.push(versions);
        variants.push(ContextSybilPolicy {
            accepted_validation_categories: vec![4, 5],
            ..base.clone()
        });
        variants.push(ContextSybilPolicy {
            device_attestation_max_age_secs: 2_591_999,
            ..base.clone()
        });
        let mut verifier = base.clone();
        if let Some(first) = verifier.accepted_android_packages.first_mut() {
            first.verifier_identifier = fixture_identifier("another verifier");
        }
        variants.push(verifier);
        let mut challenge_changed = base;
        challenge_changed.device_attestation_challenge[31] ^= 1;
        variants.push(challenge_changed);
        assert_eq!(variants.len(), 6);
        for variant in &variants {
            assert_ne!(policy_digest(variant.validated()?)?, pinned, "{variant:?}");
        }
        Ok(())
    }
}
