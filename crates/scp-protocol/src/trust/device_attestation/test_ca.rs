//! A test certificate authority shaped like Apple's App Attest chain, and the
//! attestation-object fixture the App Attest tests mutate.
//!
//! The root and the intermediate are P-384 keys from
//! `scp_crypto::p384::P384SecretKey::from_seed`; the leaf key is a P-256 key
//! from `scp_crypto::p256`. The DER and CBOR writers here share no code with
//! the reader under test: each writes exactly the bytes a test asks for, so a
//! test can build an encoding the reader must refuse.

use scp_crypto::p256::P256SecretKey;
use scp_crypto::p384::{self, P384SecretKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::app_attest::{
    self, AppAttestCheck, AppAttestRead, AppAttestRoot, CheckFn, ClientData, Run,
};
use crate::trust::sybil::{AcceptedAppId, ApplePlatform, ContextSybilPolicy};

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;
pub(super) type BoxResult<T> = Result<T, Box<dyn std::error::Error>>;

// ── DER writer ──────────────────────────────────────────────────────────────

/// A DER definite length, minimal.
pub(super) fn der_len(len: usize) -> Vec<u8> {
    match u8::try_from(len) {
        Ok(short) if short < 0x80 => vec![short],
        _ => {
            let bytes = len.to_be_bytes();
            let start = bytes
                .iter()
                .position(|b| *b != 0)
                .unwrap_or(bytes.len() - 1);
            let significant = bytes.get(start..).unwrap_or_default();
            let mut out = vec![0x80 | u8::try_from(significant.len()).unwrap_or(0)];
            out.extend_from_slice(significant);
            out
        }
    }
}

/// A TLV whose tag may be several bytes.
pub(super) fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

pub(super) fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(&[0x30], &parts.concat())
}

pub(super) fn oid(content: &[u8]) -> Vec<u8> {
    tlv(&[0x06], content)
}

pub(super) fn octets(content: &[u8]) -> Vec<u8> {
    tlv(&[0x04], content)
}

/// `[n] EXPLICIT`, constructed context-specific, `n` below 31.
pub(super) fn explicit(number: u8, content: &[u8]) -> Vec<u8> {
    tlv(&[0xa0 | number], content)
}

pub(super) fn integer(magnitude: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    if magnitude.first().is_none_or(|b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(magnitude);
    tlv(&[0x02], &content)
}

/// `UTCTime` for a Unix time between 1950 and 2049.
pub(super) fn utc_time(secs: u64) -> BoxResult<Vec<u8>> {
    let date = der::DateTime::from_unix_duration(core::time::Duration::from_secs(secs))?;
    let text = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        date.year() % 100,
        date.month(),
        date.day(),
        date.hour(),
        date.minutes(),
        date.seconds()
    );
    Ok(tlv(&[0x17], text.as_bytes()))
}

pub(super) fn name(common_name: &str) -> Vec<u8> {
    let attribute = seq(&[
        &oid(&[0x55, 0x04, 0x03]),
        &tlv(&[0x0c], common_name.as_bytes()),
    ]);
    seq(&[&tlv(&[0x31], &attribute)])
}

/// DER content of OID 1.2.840.10045.4.3.4, ecdsa-with-SHA512.
const OID_ECDSA_WITH_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
/// DER content of OID 1.2.840.113549.1.1.11, sha256WithRSAEncryption.
const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

/// A signature algorithm a test certificate names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Alg {
    /// ecdsa-with-SHA256, parameters absent.
    Sha256,
    /// ecdsa-with-SHA384, parameters absent.
    Sha384,
    /// ecdsa-with-SHA512, parameters absent.
    Sha512,
    /// ecdsa-with-SHA256 with `NULL` parameters.
    Sha256Null,
    /// sha256WithRSAEncryption with `NULL` parameters.
    Rsa,
}

impl Alg {
    pub(super) fn identifier(self) -> Vec<u8> {
        use super::x509::{OID_ECDSA_WITH_SHA256, OID_ECDSA_WITH_SHA384};
        const NULL: &[u8] = &[0x05, 0x00];
        match self {
            Self::Sha256 => seq(&[&oid(OID_ECDSA_WITH_SHA256)]),
            Self::Sha384 => seq(&[&oid(OID_ECDSA_WITH_SHA384)]),
            Self::Sha512 => seq(&[&oid(OID_ECDSA_WITH_SHA512)]),
            Self::Sha256Null => seq(&[&oid(OID_ECDSA_WITH_SHA256), NULL]),
            Self::Rsa => seq(&[&oid(OID_SHA256_WITH_RSA), NULL]),
        }
    }

    /// The digest ECDSA signs under this algorithm with a P-384 key: SHA-512
    /// is truncated to the 48-byte order length, so the signature is the one
    /// a reader that accepted ecdsa-with-SHA512 would verify.
    pub(super) fn digest(self, tbs: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 | Self::Sha256Null | Self::Rsa => Sha256::digest(tbs).to_vec(),
            Self::Sha384 => Sha384::digest(tbs).to_vec(),
            Self::Sha512 => Sha512::digest(tbs).get(..48).unwrap_or_default().to_vec(),
        }
    }
}

/// A subject public key a test certificate carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Curve {
    P256,
    P384,
    /// A 65-byte P-256 encoding whose point is not on the curve.
    P256Invalid,
    /// A 97-byte P-384 encoding whose point is not on the curve.
    P384Invalid,
}

/// `point` with its last byte flipped: the same `x` with a `y` that is not
/// either of the two curve solutions.
fn off_curve(point: &[u8]) -> Vec<u8> {
    let mut out = point.to_vec();
    if let Some(last) = out.last_mut() {
        *last ^= 0x01;
    }
    out
}

pub(super) fn spki(curve: Curve, point: &[u8]) -> Vec<u8> {
    use super::x509::{OID_EC_PUBLIC_KEY, OID_PRIME256V1, OID_SECP384R1};
    let curve_oid = match curve {
        Curve::P256 | Curve::P256Invalid => OID_PRIME256V1,
        Curve::P384 | Curve::P384Invalid => OID_SECP384R1,
    };
    let mut bits = vec![0x00];
    bits.extend_from_slice(point);
    seq(&[
        &seq(&[&oid(OID_EC_PUBLIC_KEY), &oid(curve_oid)]),
        &tlv(&[0x03], &bits),
    ])
}

/// One certificate to issue.
#[derive(Debug, Clone)]
pub(super) struct CertSpec {
    /// The algorithm `tbsCertificate.signature` names; the issuer signs the
    /// digest this algorithm defines.
    pub(super) inner_alg: Alg,
    /// The outer `signatureAlgorithm`.
    pub(super) outer_alg: Alg,
    pub(super) not_before: u64,
    pub(super) not_after: u64,
    /// The subject key's curve, `None` for the role's own curve.
    pub(super) curve_override: Option<Curve>,
    pub(super) high_s: bool,
    pub(super) unused_bits: u8,
}

impl CertSpec {
    fn new(alg: Alg, not_before: u64, not_after: u64) -> Self {
        Self {
            inner_alg: alg,
            outer_alg: alg,
            not_before,
            not_after,
            curve_override: None,
            high_s: false,
            unused_bits: 0,
        }
    }
}

/// An issued certificate's parts, so a test can reassemble them with other
/// encodings.
#[derive(Debug, Clone)]
pub(super) struct Issued {
    pub(super) tbs: Vec<u8>,
    pub(super) outer_alg: Vec<u8>,
    pub(super) unused_bits: u8,
    /// The strict-DER `ECDSA-Sig-Value`.
    pub(super) signature: Vec<u8>,
    /// The digest the issuer signed.
    pub(super) digest: Vec<u8>,
}

impl Issued {
    /// The certificate in DER.
    pub(super) fn der(&self) -> Vec<u8> {
        let mut bits = vec![self.unused_bits];
        bits.extend_from_slice(&self.signature);
        seq(&[&self.tbs, &self.outer_alg, &tlv(&[0x03], &bits)])
    }
}

/// One extension a test certificate carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TestExtension {
    pub(super) oid: Vec<u8>,
    /// Written as `critical BOOLEAN TRUE` when set, omitted otherwise.
    pub(super) critical: bool,
    pub(super) value: Vec<u8>,
}

impl TestExtension {
    /// A non-critical extension.
    pub(super) fn plain(oid: &[u8], value: Vec<u8>) -> Self {
        Self {
            oid: oid.to_vec(),
            critical: false,
            value,
        }
    }

    /// A critical extension.
    pub(super) fn critical(oid: &[u8], value: Vec<u8>) -> Self {
        Self {
            oid: oid.to_vec(),
            critical: true,
            value,
        }
    }

    /// The DER `Extension`.
    pub(super) fn der(&self) -> Vec<u8> {
        if self.critical {
            seq(&[&oid(&self.oid), &[0x01, 0x01, 0xff], &octets(&self.value)])
        } else {
            seq(&[&oid(&self.oid), &octets(&self.value)])
        }
    }
}

/// basicConstraints `cA TRUE, pathLenConstraint 0`, as Apple's intermediate
/// writes it.
pub(super) const BASIC_CONSTRAINTS_CA: [u8; 8] = [0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00];
/// basicConstraints with `cA` omitted (FALSE), as Apple's leaf writes it.
pub(super) const BASIC_CONSTRAINTS_END_ENTITY: [u8; 2] = [0x30, 0x00];
/// keyUsage keyCertSign and cRLSign.
pub(super) const KEY_USAGE_CA: [u8; 4] = [0x03, 0x02, 0x01, 0x06];
/// keyUsage digitalSignature.
pub(super) const KEY_USAGE_DIGITAL_SIGNATURE: [u8; 4] = [0x03, 0x02, 0x07, 0x80];

/// The critical basicConstraints and keyUsage of a certificate authority.
pub(super) fn ca_extensions() -> Vec<TestExtension> {
    use super::x509::{OID_BASIC_CONSTRAINTS, OID_KEY_USAGE};
    vec![
        TestExtension::critical(OID_BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_CA.to_vec()),
        TestExtension::critical(OID_KEY_USAGE, KEY_USAGE_CA.to_vec()),
    ]
}

/// The critical basicConstraints and keyUsage of a credential certificate.
pub(super) fn end_entity_extensions() -> Vec<TestExtension> {
    use super::x509::{OID_BASIC_CONSTRAINTS, OID_KEY_USAGE};
    vec![
        TestExtension::critical(OID_BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_END_ENTITY.to_vec()),
        TestExtension::critical(OID_KEY_USAGE, KEY_USAGE_DIGITAL_SIGNATURE.to_vec()),
    ]
}

fn issue(
    spec: &CertSpec,
    serial: u8,
    issuer_name: &str,
    subject_name: &str,
    subject_key: &[u8],
    extensions: &[TestExtension],
    issuer: &P384SecretKey,
) -> BoxResult<Issued> {
    let mut fields = vec![
        explicit(0, &integer(&[2])),
        integer(&[serial]),
        spec.inner_alg.identifier(),
        name(issuer_name),
        seq(&[&utc_time(spec.not_before)?, &utc_time(spec.not_after)?]),
        name(subject_name),
        subject_key.to_vec(),
    ];
    if !extensions.is_empty() {
        let list: Vec<Vec<u8>> = extensions.iter().map(TestExtension::der).collect();
        let list: Vec<&[u8]> = list.iter().map(Vec::as_slice).collect();
        fields.push(explicit(3, &seq(&list)));
    }
    let fields: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let tbs = seq(&fields);
    let digest = spec.inner_alg.digest(&tbs);
    let signature = p384::sign_prehash_der(issuer, &digest, spec.high_s)?;
    Ok(Issued {
        tbs,
        outer_alg: spec.outer_alg.identifier(),
        unused_bits: spec.unused_bits,
        signature,
        digest,
    })
}

// ── CBOR writer ─────────────────────────────────────────────────────────────

/// A CBOR head with the shortest argument.
pub(super) fn cbor_head(major: u8, n: u64) -> Vec<u8> {
    let major = major << 5;
    match n {
        0..=23 => vec![major | u8::try_from(n).unwrap_or(0)],
        24..=0xff => vec![major | 0x18, u8::try_from(n).unwrap_or(0)],
        0x100..=0xffff => {
            let mut out = vec![major | 0x19];
            out.extend_from_slice(&u16::try_from(n).unwrap_or(0).to_be_bytes());
            out
        }
        0x1_0000..=0xffff_ffff => {
            let mut out = vec![major | 0x1a];
            out.extend_from_slice(&u32::try_from(n).unwrap_or(0).to_be_bytes());
            out
        }
        _ => {
            let mut out = vec![major | 0x1b];
            out.extend_from_slice(&n.to_be_bytes());
            out
        }
    }
}

fn len64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

pub(super) fn cbor_bytes(content: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(2, len64(content.len()));
    out.extend_from_slice(content);
    out
}

pub(super) fn cbor_text(text: &str) -> Vec<u8> {
    let mut out = cbor_head(3, len64(text.len()));
    out.extend_from_slice(text.as_bytes());
    out
}

/// An array of already-encoded items.
pub(super) fn cbor_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = cbor_head(4, len64(items.len()));
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// A map of already-encoded pairs, written in the order given.
pub(super) fn cbor_map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = cbor_head(5, len64(pairs.len()));
    for (key, value) in pairs {
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }
    out
}

/// A negative integer `-1 - n`.
fn cbor_negative(n: u64) -> Vec<u8> {
    cbor_head(1, n)
}

/// The canonical `COSE_Key` of a P-256 point (RFC 9053 §7.1.1, EC2, ES256).
pub(super) fn cose_key(point: &[u8; 65]) -> Vec<u8> {
    let x = point.get(1..33).unwrap_or_default();
    let y = point.get(33..65).unwrap_or_default();
    cbor_map(&[
        (cbor_head(0, 1), cbor_head(0, 2)),
        (cbor_head(0, 3), cbor_negative(6)),
        (cbor_negative(0), cbor_head(0, 1)),
        (cbor_negative(1), cbor_bytes(x)),
        (cbor_negative(2), cbor_bytes(y)),
    ])
}

/// The canonical attestation object of three parts.
pub(super) fn attestation_object(auth_data: &[u8], leaf: &[u8], intermediate: &[u8]) -> Vec<u8> {
    cbor_map(&[
        (cbor_text("fmt"), cbor_text("apple-appattest")),
        (
            cbor_text("attStmt"),
            cbor_map(&[(
                cbor_text("x5c"),
                cbor_array(&[cbor_bytes(leaf), cbor_bytes(intermediate)]),
            )]),
        ),
        (cbor_text("authData"), cbor_bytes(auth_data)),
    ])
}

// ── Apple extensions ────────────────────────────────────────────────────────

/// Extension 8.2's value for a nonce.
pub(super) fn nonce_extension(nonce: &[u8]) -> Vec<u8> {
    seq(&[&explicit(1, &octets(nonce))])
}

/// Extension 8.6's value for an `aclBlob`.
pub(super) fn acl_blob_extension(blob: &[u8]) -> Vec<u8> {
    seq(&[&explicit(3, &octets(blob))])
}

/// Extension 8.7's value with a `[1026]` element naming `system`.
pub(super) fn platform_extension(system: &[u8]) -> Vec<u8> {
    seq(&[&tlv(&[0xbf, 0x88, 0x02], &octets(system))])
}

pub(super) use super::app_attest::MACOS_ACL_BLOB;

// ── Timing bounds ───────────────────────────────────────────────────────────

/// The number of keys in the duplicate-check timing tests: more than a
/// 4 MiB record can hold as distinct keys of the shortest form, so the bound
/// covers every input a reader can be handed.
pub(super) const MANY: u64 = 47_500;

/// The time bound of the timing tests. A pairwise comparison of `MANY` keys
/// makes over 10^9 comparisons and takes tens of seconds in a debug build;
/// a sort takes milliseconds.
pub(super) const MANY_BOUND: std::time::Duration = std::time::Duration::from_secs(2);

// ── Fixture ─────────────────────────────────────────────────────────────────

/// The leaf `notBefore` of the valid fixture: 2027-01-15T08:00:00Z.
pub(super) const T0: u64 = 1_800_000_000;
pub(super) const DAY: u64 = 86_400;
pub(super) const APP_ID: &str = "TEAMID1234.org.example.app";
/// The root's subject and issuer common name.
pub(super) const ROOT_NAME: &str = "Test App Attestation Root CA";
/// The intermediate's subject common name.
pub(super) const INTERMEDIATE_NAME: &str = "Test App Attestation CA 1";
pub(super) const MAX_AGE_SECS: u64 = 30 * DAY;
pub(super) const AAGUID_PRODUCTION: [u8; 16] = *b"appattest\0\0\0\0\0\0\0";
pub(super) const AAGUID_DEVELOPMENT: [u8; 16] = *b"appattestdevelop";
/// `authData` flags: attested credential data and extension data present.
pub(super) const FLAGS_AT_ED: u8 = 0x40 | 0x80;

/// How the leaf's extension 8.2 is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Nonce {
    /// The nonce of the fixture's `authData` and binding digest.
    Derived,
    /// The nonce of the fixture's `authData` and this binding digest.
    ForDigest([u8; 32]),
    /// No extension 8.2.
    Absent,
    /// This extension value.
    Raw(Vec<u8>),
}

/// The fixture's credential ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CredentialId {
    /// SHA-256 of the leaf key's point.
    Derived,
    /// These bytes.
    Raw(Vec<u8>),
}

/// Rewrites one part after it is built.
pub(super) type BytesHook = fn(&mut Vec<u8>);
/// Rewrites a certificate from its issued parts.
pub(super) type CertHook = fn(&Issued) -> Vec<u8>;
/// Builds the attestation object from the finished parts.
pub(super) type ObjectHook = fn(&Built) -> Vec<u8>;

/// Every input of one test read. `Fixture::valid()` reads `Verified`; a test
/// changes fields, and [`Fixture::build`] re-derives the credential ID, the
/// nonce and the signatures from them.
#[derive(Debug, Clone)]
pub(super) struct Fixture {
    pub(super) root_seed: [u8; 32],
    pub(super) intermediate_seed: [u8; 32],
    pub(super) leaf_scalar: [u8; 32],
    pub(super) root: CertSpec,
    pub(super) intermediate: CertSpec,
    pub(super) leaf: CertSpec,
    pub(super) nonce: Nonce,
    /// Extension 8.6's value, `None` for no 8.6.
    pub(super) acl_blob: Option<Vec<u8>>,
    /// Extension 8.7's value, `None` for no 8.7.
    pub(super) platform: Option<Vec<u8>>,
    /// The leaf's extensions before the Apple ones.
    pub(super) leaf_extensions: Vec<TestExtension>,
    /// Extensions added to the leaf after the Apple ones.
    pub(super) extra_leaf_extensions: Vec<TestExtension>,
    /// The intermediate's extensions.
    pub(super) intermediate_extensions: Vec<TestExtension>,
    /// The leaf's `issuer` common name.
    pub(super) leaf_issuer_name: String,
    /// The intermediate's `issuer` common name.
    pub(super) intermediate_issuer_name: String,
    pub(super) rp_id: String,
    pub(super) flags: u8,
    pub(super) counter: u32,
    pub(super) aaguid: [u8; 16],
    pub(super) credential_id: CredentialId,
    /// The `L` field, `None` for the credential ID's length.
    pub(super) credential_id_length: Option<u16>,
    /// The COSE key bytes, `None` for the leaf key's canonical COSE key.
    pub(super) cose_key: Option<Vec<u8>>,
    /// The extensions map bytes after the COSE key, `None` for none.
    pub(super) extensions: Option<Vec<u8>>,
    /// Applied to `authData` before the nonce is derived.
    pub(super) auth_data_hook: Option<BytesHook>,
    pub(super) leaf_hook: Option<CertHook>,
    pub(super) intermediate_hook: Option<CertHook>,
    pub(super) object_hook: Option<ObjectHook>,
    /// The root the read verifies to, `None` for the fixture's own root.
    pub(super) anchor_seed: Option<[u8; 32]>,
    pub(super) binding_digest: [u8; 32],
    pub(super) now_secs: u64,
    pub(super) policy: ContextSybilPolicy,
}

/// The extensions map holding only a validation category.
pub(super) fn extensions_with_category(category: &[u8]) -> Vec<u8> {
    cbor_map(&[(
        cbor_text("apple_validation_category_01"),
        cbor_bytes(category),
    )])
}

/// A policy accepting [`APP_ID`] on one platform.
pub(super) fn policy_for(platform: ApplePlatform) -> ContextSybilPolicy {
    let mut policy = ContextSybilPolicy::standard();
    policy.device_attestation_challenge = [0x11; 32];
    policy.device_attestation_max_age_secs = MAX_AGE_SECS;
    policy.accepted_app_ids = vec![AcceptedAppId {
        app_id: APP_ID.to_owned(),
        platform,
        accepted_bundle_versions: Vec::new(),
    }];
    policy.accepted_validation_categories = Vec::new();
    policy.require_validation_category = false;
    policy
}

/// The parts [`Fixture::build`] produced.
#[derive(Debug, Clone)]
pub(super) struct Built {
    pub(super) root: Vec<u8>,
    pub(super) anchor: Vec<u8>,
    pub(super) intermediate: Vec<u8>,
    pub(super) leaf: Vec<u8>,
    pub(super) intermediate_issued: Issued,
    pub(super) leaf_issued: Issued,
    pub(super) auth_data: Vec<u8>,
    pub(super) object: Vec<u8>,
    pub(super) leaf_point: [u8; 65],
}

impl Fixture {
    /// An iOS attestation that reads `Verified`.
    pub(super) fn valid() -> Self {
        Self {
            root_seed: [0x01; 32],
            intermediate_seed: [0x02; 32],
            leaf_scalar: [0x03; 32],
            root: CertSpec::new(Alg::Sha384, T0 - 3650 * DAY, T0 + 3650 * DAY),
            intermediate: CertSpec::new(Alg::Sha384, T0 - 365 * DAY, T0 + 365 * DAY),
            leaf: CertSpec::new(Alg::Sha256, T0, T0 + 3 * DAY),
            nonce: Nonce::Derived,
            acl_blob: None,
            platform: Some(platform_extension(b"iphoneos")),
            leaf_extensions: end_entity_extensions(),
            extra_leaf_extensions: Vec::new(),
            intermediate_extensions: ca_extensions(),
            leaf_issuer_name: INTERMEDIATE_NAME.to_owned(),
            intermediate_issuer_name: ROOT_NAME.to_owned(),
            rp_id: APP_ID.to_owned(),
            flags: FLAGS_AT_ED,
            counter: 0,
            aaguid: AAGUID_PRODUCTION,
            credential_id: CredentialId::Derived,
            credential_id_length: None,
            cose_key: None,
            extensions: Some(extensions_with_category(&4u32.to_le_bytes())),
            auth_data_hook: None,
            leaf_hook: None,
            intermediate_hook: None,
            object_hook: None,
            anchor_seed: None,
            binding_digest: [0x5a; 32],
            now_secs: T0 + 60,
            policy: policy_for(ApplePlatform::Ios),
        }
    }

    /// A macOS attestation that reads `Verified`.
    pub(super) fn valid_mac() -> Self {
        let mut fixture = Self::valid();
        fixture.acl_blob = Some(acl_blob_extension(&MACOS_ACL_BLOB));
        fixture.platform = Some(platform_extension(b"macosx"));
        fixture.policy = policy_for(ApplePlatform::MacOs);
        fixture
    }

    pub(super) fn leaf_point(&self) -> BoxResult<[u8; 65]> {
        Ok(P256SecretKey::from_scalar_bytes(&self.leaf_scalar)?
            .public_key()
            .to_uncompressed())
    }

    /// The `authData` bytes, before the hook.
    fn auth_data(&self, point: &[u8; 65]) -> Vec<u8> {
        let credential_id = match &self.credential_id {
            CredentialId::Derived => Sha256::digest(point).to_vec(),
            CredentialId::Raw(bytes) => bytes.clone(),
        };
        let length = self
            .credential_id_length
            .unwrap_or_else(|| u16::try_from(credential_id.len()).unwrap_or(u16::MAX));
        let mut out = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        out.push(self.flags);
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.aaguid);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&credential_id);
        out.extend(self.cose_key.clone().unwrap_or_else(|| cose_key(point)));
        if let Some(extensions) = &self.extensions {
            out.extend_from_slice(extensions);
        }
        out
    }

    /// The leaf's extensions: 8.2 over `auth_data`, then 8.6, 8.7 and the
    /// extra ones.
    fn all_leaf_extensions(&self, auth_data: &[u8]) -> Vec<TestExtension> {
        let nonce_for = |digest: &[u8; 32]| {
            let mut hasher = Sha256::new();
            hasher.update(auth_data);
            hasher.update(digest);
            nonce_extension(&hasher.finalize())
        };
        let mut extensions = self.leaf_extensions.clone();
        match &self.nonce {
            Nonce::Derived => {
                extensions.push(TestExtension::plain(
                    OID_NONCE,
                    nonce_for(&self.binding_digest),
                ));
            }
            Nonce::ForDigest(digest) => {
                extensions.push(TestExtension::plain(OID_NONCE, nonce_for(digest)));
            }
            Nonce::Absent => {}
            Nonce::Raw(value) => extensions.push(TestExtension::plain(OID_NONCE, value.clone())),
        }
        if let Some(value) = &self.acl_blob {
            extensions.push(TestExtension::plain(OID_ACL_BLOB, value.clone()));
        }
        if let Some(value) = &self.platform {
            extensions.push(TestExtension::plain(OID_PLATFORM, value.clone()));
        }
        extensions.extend(self.extra_leaf_extensions.iter().cloned());
        extensions
    }

    /// Builds every part.
    pub(super) fn build(&self) -> BoxResult<Built> {
        let root_key = P384SecretKey::from_seed(&self.root_seed)?;
        let intermediate_key = P384SecretKey::from_seed(&self.intermediate_seed)?;
        let root_point = root_key.public_key()?.to_uncompressed();
        let intermediate_point = intermediate_key.public_key()?.to_uncompressed();
        let leaf_point = self.leaf_point()?;
        // A curve override writes a valid point of the other curve.
        let p256_stand_in = leaf_point;
        let key_for = |own: Curve, point: &[u8], spec: &CertSpec| match spec.curve_override {
            None => spki(own, point),
            Some(Curve::P256) => spki(Curve::P256, &p256_stand_in),
            Some(Curve::P384) => spki(Curve::P384, &root_point),
            Some(Curve::P256Invalid) => spki(Curve::P256, &off_curve(&p256_stand_in)),
            Some(Curve::P384Invalid) => spki(Curve::P384, &off_curve(&root_point)),
        };

        let root = issue(
            &self.root,
            1,
            ROOT_NAME,
            ROOT_NAME,
            &key_for(Curve::P384, &root_point, &self.root),
            &ca_extensions(),
            &root_key,
        )?
        .der();
        // A foreign anchor carries the fixture root's name, so only its key
        // differs and only the intermediate's signature can refuse it.
        let anchor = match self.anchor_seed {
            None => root.clone(),
            Some(seed) => {
                let foreign = P384SecretKey::from_seed(&seed)?;
                let point = foreign.public_key()?.to_uncompressed();
                issue(
                    &self.root,
                    9,
                    ROOT_NAME,
                    ROOT_NAME,
                    &spki(Curve::P384, &point),
                    &ca_extensions(),
                    &foreign,
                )?
                .der()
            }
        };
        let intermediate_issued = issue(
            &self.intermediate,
            2,
            &self.intermediate_issuer_name,
            INTERMEDIATE_NAME,
            &key_for(Curve::P384, &intermediate_point, &self.intermediate),
            &self.intermediate_extensions,
            &root_key,
        )?;
        let intermediate = self.intermediate_hook.map_or_else(
            || intermediate_issued.der(),
            |hook| hook(&intermediate_issued),
        );

        let mut auth_data = self.auth_data(&leaf_point);
        if let Some(hook) = self.auth_data_hook {
            hook(&mut auth_data);
        }
        let extensions = self.all_leaf_extensions(&auth_data);
        let leaf_issued = issue(
            &self.leaf,
            3,
            &self.leaf_issuer_name,
            "credential",
            &key_for(Curve::P256, &leaf_point, &self.leaf),
            &extensions,
            &intermediate_key,
        )?;
        let leaf = self
            .leaf_hook
            .map_or_else(|| leaf_issued.der(), |hook| hook(&leaf_issued));

        let mut built = Built {
            root,
            anchor,
            intermediate,
            leaf,
            intermediate_issued,
            leaf_issued,
            object: Vec::new(),
            auth_data,
            leaf_point,
        };
        built.object = self.object_hook.map_or_else(
            || attestation_object(&built.auth_data, &built.leaf, &built.intermediate),
            |hook| hook(&built),
        );
        Ok(built)
    }

    /// Runs `checks` on the built read against the fixture's anchor.
    pub(super) fn run(&self, checks: &[(AppAttestCheck, CheckFn)]) -> BoxResult<Run> {
        let built = self.build()?;
        let policy = self.policy.validated()?;
        let read = AppAttestRead {
            attestation_object: &built.object,
            client_data: ClientData::from_test_bytes(&self.binding_digest),
            policy,
            now_secs: self.now_secs,
            entry_id: "entry-1",
        };
        Ok(app_attest::run(
            &AppAttestRoot::from_test_der(&built.anchor),
            &read,
            checks,
        ))
    }

    /// Runs every check.
    pub(super) fn run_all(&self) -> BoxResult<Run> {
        self.run(&app_attest::APP_ATTEST_CHECKS)
    }
}

use super::x509::{
    OID_APPLE_ACL_BLOB as OID_ACL_BLOB, OID_APPLE_NONCE as OID_NONCE,
    OID_APPLE_PLATFORM as OID_PLATFORM,
};
