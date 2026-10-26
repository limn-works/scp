//! The X.509 reading App Attest check 3 needs (`09-security-model.md`
//! §9.3.1).
//!
//! A certificate is read in two steps:
//!
//! 1. [`split_certificate`] splits the outer `SEQUENCE` leniently into the
//!    `tbsCertificate` bytes, the outer `signatureAlgorithm`, the `BIT
//!    STRING`'s unused-bits count, and the signature's `r` and `s`. It
//!    accepts BER lengths and non-minimal integers, because Apple signs only
//!    `tbsCertificate`. [`rebuild_matches`] then rebuilds the certificate in
//!    DER from the signed part and `(r, s)` and compares it with the input, so
//!    every unsigned byte is fixed ("Canonical encodings" in §9.3.1).
//! 2. [`parse_tbs`] parses `tbsCertificate` as strict DER with the `der`
//!    crate and the RFC 5280 §4.1 structure check 3 states: a v3 version, the
//!    optional fields at most once each and in order, a non-empty extensions
//!    list with no OID repeated and no `critical FALSE`, and `UTCTime` for
//!    every validity time before 2050.
//!
//! [`verify_signature`] hashes `tbsCertificate` with the algorithm its
//! `signature` field names and verifies it under an issuer's P-384 key. It is
//! separate from the rebuild, so a test can show a certificate whose
//! signature verifies and whose rebuild differs.

use der::asn1::{AnyRef, GeneralizedTime, UtcTime};
use der::{Decode, Reader, SliceReader, Tag, Tagged};
use scp_crypto::p384::{P384PublicKey, verify_prehash_der_lenient};
use sha2::{Digest, Sha256, Sha384};

/// DER content of OID 1.2.840.10045.4.3.2, ecdsa-with-SHA256.
pub(super) const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// DER content of OID 1.2.840.10045.4.3.3, ecdsa-with-SHA384.
pub(super) const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// DER content of OID 1.2.840.10045.2.1, id-ecPublicKey.
pub(super) const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// DER content of OID 1.3.132.0.34, secp384r1.
pub(super) const OID_SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/// DER content of OID 1.2.840.10045.3.1.7, prime256v1 (P-256).
pub(super) const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// DER content of OID 2.5.29.19, basicConstraints.
pub(super) const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
/// DER content of OID 2.5.29.15, keyUsage.
pub(super) const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
/// DER content of OID 1.2.840.113635.100.8.2, the App Attest nonce.
pub(super) const OID_APPLE_NONCE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02];
/// DER content of OID 1.2.840.113635.100.8.6, the `aclBlob`.
pub(super) const OID_APPLE_ACL_BLOB: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x06];
/// DER content of OID 1.2.840.113635.100.8.7, the platform extension.
pub(super) const OID_APPLE_PLATFORM: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x07];

/// The critical extensions check 3 recognises on an `x5c` certificate.
pub(super) const RECOGNISED_CRITICAL_EXTENSIONS: [&[u8]; 2] =
    [OID_BASIC_CONSTRAINTS, OID_KEY_USAGE];

/// Length of a SEC1 uncompressed P-256 point.
const P256_POINT_LEN: usize = 65;
/// Length of a SEC1 uncompressed P-384 point.
const P384_POINT_LEN: usize = 97;

/// 2050-01-01T00:00:00Z in Unix seconds, the first time RFC 5280 §4.1.2.5
/// writes as `GeneralizedTime`.
const GENERALIZED_TIME_FROM_SECS: u64 = 2_524_608_000;

/// The keyCertSign bit of keyUsage (bit 5), in the first content byte after
/// the unused-bits count.
const KEY_CERT_SIGN: u8 = 0x04;

/// Why a certificate could not be read. Every value becomes
/// `Rejected{CertificateChainInvalid}` at check 3, or `MalformedToken` and
/// `PlatformUnreported` where checks 5 and 7 read an extension; the variant
/// names the defect so a test can tell which rule refused an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum CertificateMalformed {
    /// The `der` crate refused the bytes as DER.
    #[error("not strict DER")]
    NotStrictDer,
    /// A lenient TLV header ends early.
    #[error("truncated header")]
    TruncatedHeader,
    /// A lenient TLV has a tag of more than one byte.
    #[error("multi-byte tag in the outer structure")]
    MultiByteTag,
    /// A lenient TLV has the indefinite length form.
    #[error("indefinite length")]
    IndefiniteLength,
    /// A lenient TLV's length has more than four bytes.
    #[error("length longer than four bytes")]
    LengthTooLong,
    /// A lenient TLV's length runs past the input.
    #[error("content runs past the input")]
    ContentPastInput,
    /// A part of the outer `SEQUENCE` or the `ECDSA-Sig-Value` has the wrong
    /// tag.
    #[error("outer part has the wrong tag")]
    OuterTag,
    /// The `signatureValue` `BIT STRING` is empty.
    #[error("empty BIT STRING")]
    EmptyBitString,
    /// An INTEGER has no content octets (X.690 clause 8.3.1).
    #[error("empty INTEGER")]
    EmptyInteger,
    /// An INTEGER that must be non-negative is negative.
    #[error("negative INTEGER")]
    NegativeInteger,
    /// An INTEGER's first nine bits are all ones or all zeros, so a shorter
    /// encoding exists (X.690 clause 8.3.2).
    #[error("INTEGER not minimally encoded")]
    IntegerNotMinimal,
    /// The `[0]` version is absent or is not v3 (`INTEGER 2`).
    #[error("version is not v3")]
    VersionNotV3,
    /// `serialNumber` is not an INTEGER.
    #[error("serialNumber is not an INTEGER")]
    SerialNotInteger,
    /// An `AlgorithmIdentifier` does not start with an OID.
    #[error("algorithm is not an OID")]
    AlgorithmNotOid,
    /// `issuer` or `subject` is not a `SEQUENCE`.
    #[error("name is not a SEQUENCE")]
    NameNotSequence,
    /// A validity time is neither `UTCTime` nor `GeneralizedTime`.
    #[error("validity time is not a Time")]
    TimeNotTime,
    /// A validity time before 2050 is a `GeneralizedTime`; RFC 5280 §4.1.2.5
    /// requires `UTCTime` through 2049.
    #[error("GeneralizedTime before 2050")]
    GeneralizedTimeBefore2050,
    /// `subjectPublicKey` is not a `BIT STRING`.
    #[error("subjectPublicKey is not a BIT STRING")]
    KeyNotBitString,
    /// `subjectPublicKey` has unused bits.
    #[error("subjectPublicKey has unused bits")]
    KeyUnusedBits,
    /// `issuerUniqueID`, `subjectUniqueID` or `extensions` repeats or comes
    /// out of order.
    #[error("optional field repeated or out of order")]
    FieldOutOfOrder,
    /// A field after `subjectPublicKeyInfo` is none of `[1]`, `[2]` and
    /// `[3]`.
    #[error("unexpected field after subjectPublicKeyInfo")]
    UnexpectedField,
    /// The extensions `SEQUENCE` holds no extension.
    #[error("extensions SEQUENCE is empty")]
    ExtensionsEmpty,
    /// An `extnID` is not an OID.
    #[error("extnID is not an OID")]
    ExtensionIdNotOid,
    /// A `critical` BOOLEAN is present and is not DER `TRUE`; DER omits the
    /// `FALSE` default.
    #[error("critical is present and not TRUE")]
    CriticalNotTrue,
    /// An `extnValue` is not an `OCTET STRING`.
    #[error("extnValue is not an OCTET STRING")]
    ExtensionValueNotOctets,
    /// Two extensions share an OID.
    #[error("extension repeated")]
    ExtensionRepeated,
    /// An Apple extension's `SEQUENCE` does not hold the `[n]` element the
    /// reader expects.
    #[error("unexpected element")]
    UnexpectedElement,
    /// An Apple extension's element does not hold an `OCTET STRING`.
    #[error("element is not an OCTET STRING")]
    ElementNotOctets,
    /// An extension 8.7 element is not context-tagged.
    #[error("platform element is not context-tagged")]
    PlatformElementUntagged,
    /// Extension 8.7's `[1026]` repeats or is not explicit.
    #[error("[1026] repeated or not explicit")]
    SystemNameRepeatedOrImplicit,
    /// basicConstraints is not `SEQUENCE { cA BOOLEAN TRUE OPTIONAL,
    /// pathLenConstraint INTEGER OPTIONAL }` in DER.
    #[error("basicConstraints malformed")]
    BasicConstraintsMalformed,
    /// keyUsage is not a non-empty `BIT STRING`.
    #[error("keyUsage malformed")]
    KeyUsageMalformed,
    /// A `BIT STRING` declares more than 7 unused bits, or declares unused
    /// bits and holds no bit (X.690 clause 8.6.2.2 and clause 8.6.2.3).
    #[error("BIT STRING unused-bits count invalid")]
    BitStringUnusedBitsInvalid,
    /// A `BIT STRING` padding bit is one; DER sets every padding bit to zero
    /// (X.690 clause 11.2.1).
    #[error("BIT STRING padding bit not zero")]
    BitStringPaddingNotZero,
    /// A named-bit `BIT STRING` ends with a zero bit; DER removes trailing
    /// zero bits (X.690 clause 11.2.2).
    #[error("named-bit BIT STRING has a trailing zero bit")]
    BitStringTrailingZeroBit,
}

impl From<der::Error> for CertificateMalformed {
    fn from(_: der::Error) -> Self {
        Self::NotStrictDer
    }
}

/// Why [`verify_signature`] refused a certificate's signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignatureFault {
    /// `tbsCertificate.signature` names an algorithm check 3 does not accept.
    UnsupportedAlgorithm,
    /// The signature does not verify under the issuer's key.
    DoesNotVerify,
}

/// The parts of a certificate's outer `SEQUENCE`, read leniently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CertificateParts<'a> {
    /// The `tbsCertificate` TLV, as received.
    pub(super) tbs: &'a [u8],
    /// The outer `signatureAlgorithm` TLV, as received.
    pub(super) outer_algorithm: &'a [u8],
    /// The `signatureValue` `BIT STRING`'s unused-bits count.
    pub(super) unused_bits: u8,
    /// The signature's `r`, big-endian, leading zero bytes removed.
    pub(super) r: &'a [u8],
    /// The signature's `s`, big-endian, leading zero bytes removed.
    pub(super) s: &'a [u8],
}

/// One TLV: its tag byte, the whole TLV, its content, and the bytes after it.
type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// One extension of a parsed `tbsCertificate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Extension {
    /// The `extnID` OID content.
    pub(super) oid: Vec<u8>,
    /// Whether the extension carries `critical TRUE`.
    pub(super) critical: bool,
    /// The `extnValue` content.
    pub(super) value: Vec<u8>,
}

/// One lenient TLV: its tag byte, the whole TLV, its content, and the bytes
/// after it. Accepts single-byte tags and any definite length form of up to
/// four length bytes, minimal or not. Refuses the indefinite form, because a
/// definite outer length is needed to find the parts.
fn lenient_tlv(input: &[u8]) -> Result<Tlv<'_>, CertificateMalformed> {
    let [tag, first, rest @ ..] = input else {
        return Err(CertificateMalformed::TruncatedHeader);
    };
    if tag & 0x1f == 0x1f {
        return Err(CertificateMalformed::MultiByteTag);
    }
    let (len, rest) = match *first {
        short @ 0x00..=0x7f => (usize::from(short), rest),
        0x80 => return Err(CertificateMalformed::IndefiniteLength),
        long @ 0x81..=0x84 => {
            let count = usize::from(long & 0x7f);
            let (len_bytes, rest) = rest
                .split_at_checked(count)
                .ok_or(CertificateMalformed::TruncatedHeader)?;
            let len = len_bytes
                .iter()
                .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
            (len, rest)
        }
        _ => return Err(CertificateMalformed::LengthTooLong),
    };
    let (content, after) = rest
        .split_at_checked(len)
        .ok_or(CertificateMalformed::ContentPastInput)?;
    let header_len = input.len() - rest.len();
    let whole = input
        .get(..header_len + len)
        .ok_or(CertificateMalformed::ContentPastInput)?;
    Ok((*tag, whole, content, after))
}

/// Checks a DER INTEGER's content octets: present and minimally encoded
/// (X.690 clause 8.3.1 and clause 8.3.2).
fn strict_integer(content: &[u8]) -> Result<(), CertificateMalformed> {
    match content {
        [] => Err(CertificateMalformed::EmptyInteger),
        [0x00, next, ..] if next & 0x80 == 0 => Err(CertificateMalformed::IntegerNotMinimal),
        [0xff, next, ..] if next & 0x80 != 0 => Err(CertificateMalformed::IntegerNotMinimal),
        _ => Ok(()),
    }
}

/// Checks a DER INTEGER that must be non-negative.
fn strict_unsigned(content: &[u8]) -> Result<(), CertificateMalformed> {
    strict_integer(content)?;
    match content.first() {
        Some(first) if first & 0x80 != 0 => Err(CertificateMalformed::NegativeInteger),
        _ => Ok(()),
    }
}

/// The content bits of a DER `BIT STRING` that holds a named-bit list such
/// as keyUsage: the unused-bits count is at most 7, is 0 when no bit
/// follows, every padding bit is zero (X.690 clause 11.2.1), and the last used
/// bit is one (X.690 clause 11.2.2).
fn named_bits(content: &[u8]) -> Result<&[u8], CertificateMalformed> {
    let [unused, bits @ ..] = content else {
        return Err(CertificateMalformed::KeyUsageMalformed);
    };
    let unused = *unused;
    if unused > 7 || (bits.is_empty() && unused != 0) {
        return Err(CertificateMalformed::BitStringUnusedBitsInvalid);
    }
    if let Some(last) = bits.last() {
        if last & ((1u8 << unused) - 1) != 0 {
            return Err(CertificateMalformed::BitStringPaddingNotZero);
        }
        if (last >> unused) & 1 == 0 {
            return Err(CertificateMalformed::BitStringTrailingZeroBit);
        }
    }
    Ok(bits)
}

/// A lenient non-negative INTEGER's magnitude, leading zero bytes removed.
fn lenient_unsigned(content: &[u8]) -> Result<&[u8], CertificateMalformed> {
    match content.first() {
        None => Err(CertificateMalformed::EmptyInteger),
        Some(first) if first & 0x80 != 0 => Err(CertificateMalformed::NegativeInteger),
        Some(_) => {
            let start = content
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(content.len());
            content
                .get(start..)
                .ok_or(CertificateMalformed::EmptyInteger)
        }
    }
}

/// Splits a certificate's outer `SEQUENCE` leniently (see the module
/// documentation). Bytes after the outer `SEQUENCE`, or after its three
/// parts, are left for [`rebuild_matches`] to reject.
pub(super) fn split_certificate(der: &[u8]) -> Result<CertificateParts<'_>, CertificateMalformed> {
    let tagged = |wanted: u8, input| {
        let tlv @ (tag, ..) = lenient_tlv(input)?;
        if tag == wanted {
            Ok(tlv)
        } else {
            Err(CertificateMalformed::OuterTag)
        }
    };
    let (_, _, body, _) = tagged(0x30, der)?;
    let (_, tbs, _, rest) = tagged(0x30, body)?;
    let (_, outer_algorithm, _, rest) = tagged(0x30, rest)?;
    let (_, _, bits, _) = tagged(0x03, rest)?;
    let [unused_bits, signature @ ..] = bits else {
        return Err(CertificateMalformed::EmptyBitString);
    };
    let (_, _, sig_body, _) = tagged(0x30, signature)?;
    let (_, _, r, rest) = tagged(0x02, sig_body)?;
    let (_, _, s, _) = tagged(0x02, rest)?;
    Ok(CertificateParts {
        tbs,
        outer_algorithm,
        unused_bits: *unused_bits,
        r: lenient_unsigned(r)?,
        s: lenient_unsigned(s)?,
    })
}

/// Appends a DER length.
fn push_der_length(out: &mut Vec<u8>, len: usize) {
    match u8::try_from(len) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            let bytes = len.to_be_bytes();
            let start = bytes
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(bytes.len() - 1);
            let significant = bytes.get(start..).unwrap_or_default();
            // At most size_of::<usize>() = 8 bytes, so the count fits 0x80 | n.
            out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0x7f));
            out.extend_from_slice(significant);
        }
    }
}

/// Appends a DER TLV with a single-byte tag.
fn push_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    push_der_length(out, content.len());
    out.extend_from_slice(content);
}

/// Appends the DER INTEGER of a non-negative magnitude.
fn push_unsigned(out: &mut Vec<u8>, magnitude: &[u8]) {
    let mut content = Vec::with_capacity(magnitude.len() + 1);
    if magnitude.first().is_none_or(|byte| byte & 0x80 != 0) {
        content.push(0x00);
    }
    content.extend_from_slice(magnitude);
    push_tlv(out, 0x02, &content);
}

/// The DER `ECDSA-Sig-Value` of `r` and `s` (RFC 3279 §2.2.3).
pub(super) fn ecdsa_sig_value_der(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(r.len() + s.len() + 6);
    push_unsigned(&mut body, r);
    push_unsigned(&mut body, s);
    let mut out = Vec::with_capacity(body.len() + 3);
    push_tlv(&mut out, 0x30, &body);
    out
}

/// Rebuilds the certificate as §9.3.1 "Canonical encodings" states: the DER
/// `SEQUENCE` of the received `tbsCertificate` bytes, a copy of
/// `tbsCertificate.signature` (`inner_algorithm`, the TLV [`parse_tbs`]
/// returns), and a `BIT STRING` with zero unused bits holding the DER
/// `ECDSA-Sig-Value` of `r` and `s`.
pub(super) fn rebuild(parts: &CertificateParts<'_>, inner_algorithm: &[u8]) -> Vec<u8> {
    let signature = ecdsa_sig_value_der(parts.r, parts.s);
    let mut bits = Vec::with_capacity(signature.len() + 1);
    bits.push(0x00);
    bits.extend_from_slice(&signature);
    let mut body = Vec::with_capacity(parts.tbs.len() + inner_algorithm.len() + bits.len() + 4);
    body.extend_from_slice(parts.tbs);
    body.extend_from_slice(inner_algorithm);
    push_tlv(&mut body, 0x03, &bits);
    let mut out = Vec::with_capacity(body.len() + 4);
    push_tlv(&mut out, 0x30, &body);
    out
}

/// Whether `der` equals its rebuild.
pub(super) fn rebuild_matches(
    der: &[u8],
    parts: &CertificateParts<'_>,
    inner_algorithm: &[u8],
) -> bool {
    rebuild(parts, inner_algorithm) == der
}

/// The signature algorithm `tbsCertificate.signature` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignatureAlgorithm {
    /// ecdsa-with-SHA256 with its parameters absent.
    EcdsaSha256,
    /// ecdsa-with-SHA384 with its parameters absent.
    EcdsaSha384,
    /// Any other algorithm, or either one with parameters present.
    Unsupported,
}

/// The subject public key, classified by algorithm, curve and length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SubjectKey {
    /// id-ecPublicKey on prime256v1, a 65-byte uncompressed point.
    P256([u8; P256_POINT_LEN]),
    /// id-ecPublicKey on secp384r1, a 97-byte uncompressed point.
    P384(Vec<u8>),
    /// Any other key.
    Other,
}

/// The fields of a strictly parsed `tbsCertificate` that check 3 and the
/// later checks read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Tbs {
    /// The `signature` field's whole TLV, which the rebuild copies.
    pub(super) signature_algorithm_tlv: Vec<u8>,
    /// The algorithm that TLV names.
    pub(super) signature_algorithm: SignatureAlgorithm,
    /// The `issuer` Name's whole DER TLV.
    pub(super) issuer: Vec<u8>,
    /// `validity.notBefore`, Unix seconds.
    pub(super) not_before: u64,
    /// `validity.notAfter`, Unix seconds.
    pub(super) not_after: u64,
    /// The `subject` Name's whole DER TLV.
    pub(super) subject: Vec<u8>,
    /// The subject public key.
    pub(super) key: SubjectKey,
    /// The extensions, in certificate order. No OID repeats.
    pub(super) extensions: Vec<Extension>,
}

impl Tbs {
    /// The `extnValue` content of the extension with this OID.
    pub(super) fn extension(&self, oid: &[u8]) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|extension| extension.oid == oid)
            .map(|extension| extension.value.as_slice())
    }

    /// Whether the certificate carries a critical extension outside
    /// [`RECOGNISED_CRITICAL_EXTENSIONS`].
    pub(super) fn has_unrecognised_critical_extension(&self) -> bool {
        self.extensions.iter().any(|extension| {
            extension.critical
                && !RECOGNISED_CRITICAL_EXTENSIONS.contains(&extension.oid.as_slice())
        })
    }
}

fn expect_tag(
    any: AnyRef<'_>,
    tag: Tag,
    otherwise: CertificateMalformed,
) -> Result<(), CertificateMalformed> {
    if any.tag() == tag {
        Ok(())
    } else {
        Err(otherwise)
    }
}

fn is_context(tag: Tag, wanted: u32, wanted_constructed: bool) -> bool {
    matches!(tag, Tag::ContextSpecific { constructed, number }
        if constructed == wanted_constructed && number.value() == wanted)
}

fn time_secs(any: AnyRef<'_>) -> Result<u64, CertificateMalformed> {
    match any.tag() {
        Tag::UtcTime => Ok(any.decode_as::<UtcTime>()?.to_unix_duration().as_secs()),
        Tag::GeneralizedTime => {
            let secs = any
                .decode_as::<GeneralizedTime>()?
                .to_unix_duration()
                .as_secs();
            if secs < GENERALIZED_TIME_FROM_SECS {
                return Err(CertificateMalformed::GeneralizedTimeBefore2050);
            }
            Ok(secs)
        }
        _ => Err(CertificateMalformed::TimeNotTime),
    }
}

fn parse_signature_algorithm(tlv: &[u8]) -> Result<SignatureAlgorithm, CertificateMalformed> {
    let algorithm = AnyRef::from_der(tlv)?;
    algorithm.sequence(|reader: &mut SliceReader<'_>| {
        let oid = AnyRef::decode(reader)?;
        expect_tag(
            oid,
            Tag::ObjectIdentifier,
            CertificateMalformed::AlgorithmNotOid,
        )?;
        if !reader.is_finished() {
            // Parameters present: drain them so `sequence` sees a finished
            // reader, and classify the algorithm as unsupported.
            while !reader.is_finished() {
                AnyRef::decode(reader)?;
            }
            return Ok(SignatureAlgorithm::Unsupported);
        }
        Ok(match oid.value() {
            OID_ECDSA_WITH_SHA256 => SignatureAlgorithm::EcdsaSha256,
            OID_ECDSA_WITH_SHA384 => SignatureAlgorithm::EcdsaSha384,
            _ => SignatureAlgorithm::Unsupported,
        })
    })
}

fn parse_subject_key(spki: AnyRef<'_>) -> Result<SubjectKey, CertificateMalformed> {
    spki.sequence(|reader: &mut SliceReader<'_>| {
        let algorithm = AnyRef::decode(reader)?;
        let (algorithm_oid, curve) = algorithm.sequence(|inner: &mut SliceReader<'_>| {
            let algorithm_oid = AnyRef::decode(inner)?;
            let curve = if inner.is_finished() {
                None
            } else {
                Some(AnyRef::decode(inner)?)
            };
            Ok::<_, CertificateMalformed>((algorithm_oid, curve))
        })?;
        let bits = AnyRef::decode(reader)?;
        expect_tag(bits, Tag::BitString, CertificateMalformed::KeyNotBitString)?;
        let [0x00, point @ ..] = bits.value() else {
            return Err(CertificateMalformed::KeyUnusedBits);
        };
        let ec = algorithm_oid.tag() == Tag::ObjectIdentifier
            && algorithm_oid.value() == OID_EC_PUBLIC_KEY;
        let curve = curve
            .filter(|curve| curve.tag() == Tag::ObjectIdentifier)
            .map(AnyRef::value);
        Ok(match (ec, curve, point.len()) {
            (true, Some(OID_PRIME256V1), P256_POINT_LEN) => {
                let mut fixed = [0u8; P256_POINT_LEN];
                fixed.copy_from_slice(point);
                SubjectKey::P256(fixed)
            }
            (true, Some(OID_SECP384R1), P384_POINT_LEN) => SubjectKey::P384(point.to_vec()),
            _ => SubjectKey::Other,
        })
    })
}

/// Parses the `[3]` extensions field. Repeated OIDs are found by sorting, so
/// the cost is `O(n log n)` in the number of extensions with no cap on `n`.
fn parse_extensions(wrapper: AnyRef<'_>) -> Result<Vec<Extension>, CertificateMalformed> {
    let list = AnyRef::from_der(wrapper.value())?;
    let extensions = list.sequence(|reader: &mut SliceReader<'_>| {
        let mut extensions = Vec::new();
        while !reader.is_finished() {
            let extension = AnyRef::decode(reader)?;
            extensions.push(extension.sequence(|inner: &mut SliceReader<'_>| {
                let oid = AnyRef::decode(inner)?;
                expect_tag(
                    oid,
                    Tag::ObjectIdentifier,
                    CertificateMalformed::ExtensionIdNotOid,
                )?;
                let mut value = AnyRef::decode(inner)?;
                let critical = value.tag() == Tag::Boolean;
                if critical {
                    // DER encodes TRUE as 0xff and never encodes the FALSE
                    // default (X.690 clause 11.1 and clause 11.5).
                    if value.value() != [0xff] {
                        return Err(CertificateMalformed::CriticalNotTrue);
                    }
                    value = AnyRef::decode(inner)?;
                }
                expect_tag(
                    value,
                    Tag::OctetString,
                    CertificateMalformed::ExtensionValueNotOctets,
                )?;
                Ok(Extension {
                    oid: oid.value().to_vec(),
                    critical,
                    value: value.value().to_vec(),
                })
            })?);
        }
        Ok::<_, CertificateMalformed>(extensions)
    })?;
    if extensions.is_empty() {
        return Err(CertificateMalformed::ExtensionsEmpty);
    }
    let mut oids: Vec<&[u8]> = extensions
        .iter()
        .map(|extension| extension.oid.as_slice())
        .collect();
    oids.sort_unstable();
    if oids.windows(2).any(|pair| match pair {
        [left, right] => left == right,
        _ => false,
    }) {
        return Err(CertificateMalformed::ExtensionRepeated);
    }
    Ok(extensions)
}

/// The DER bytes of `version [0] EXPLICIT INTEGER 2` (v3) after its tag and
/// length.
const VERSION_V3_CONTENT: [u8; 3] = [0x02, 0x01, 0x02];

/// The context tag number of an optional field after
/// `subjectPublicKeyInfo`: `issuerUniqueID` `[1]` and `subjectUniqueID` `[2]`
/// are implicit (primitive) and `extensions` `[3]` is explicit (constructed).
fn optional_field_number(tag: Tag) -> Option<u32> {
    [(1, false), (2, false), (3, true)]
        .into_iter()
        .find(|(number, constructed)| is_context(tag, *number, *constructed))
        .map(|(number, _)| number)
}

/// Parses `tbsCertificate` as strict DER with the RFC 5280 §4.1 structure
/// §9.3.1 check 3 requires.
pub(super) fn parse_tbs(tbs: &[u8]) -> Result<Tbs, CertificateMalformed> {
    let tbs = AnyRef::from_der(tbs)?;
    tbs.sequence(|reader: &mut SliceReader<'_>| {
        if !is_context(Tag::peek(reader)?, 0, true) {
            return Err(CertificateMalformed::VersionNotV3);
        }
        if AnyRef::decode(reader)?.value() != VERSION_V3_CONTENT {
            return Err(CertificateMalformed::VersionNotV3);
        }
        let serial = AnyRef::decode(reader)?;
        expect_tag(serial, Tag::Integer, CertificateMalformed::SerialNotInteger)?;
        // RFC 5280 §4.1.2.2 asks relying parties to tolerate a negative
        // serial, so only the DER encoding rules apply here.
        strict_integer(serial.value())?;
        let signature_algorithm_tlv = reader.tlv_bytes()?.to_vec();
        let signature_algorithm = parse_signature_algorithm(&signature_algorithm_tlv)?;
        let issuer = reader.tlv_bytes()?.to_vec();
        expect_tag(
            AnyRef::from_der(&issuer)?,
            Tag::Sequence,
            CertificateMalformed::NameNotSequence,
        )?;
        let validity = AnyRef::decode(reader)?;
        let (not_before, not_after) = validity.sequence(|inner: &mut SliceReader<'_>| {
            let not_before = time_secs(AnyRef::decode(inner)?)?;
            let not_after = time_secs(AnyRef::decode(inner)?)?;
            Ok::<_, CertificateMalformed>((not_before, not_after))
        })?;
        let subject = reader.tlv_bytes()?.to_vec();
        expect_tag(
            AnyRef::from_der(&subject)?,
            Tag::Sequence,
            CertificateMalformed::NameNotSequence,
        )?;
        let key = parse_subject_key(AnyRef::decode(reader)?)?;
        let mut extensions = Vec::new();
        let mut last_field = 0;
        while !reader.is_finished() {
            let field = AnyRef::decode(reader)?;
            let number =
                optional_field_number(field.tag()).ok_or(CertificateMalformed::UnexpectedField)?;
            if number <= last_field {
                return Err(CertificateMalformed::FieldOutOfOrder);
            }
            last_field = number;
            if number == 3 {
                extensions = parse_extensions(field)?;
            }
        }
        Ok(Tbs {
            signature_algorithm_tlv,
            signature_algorithm,
            issuer,
            not_before,
            not_after,
            subject,
            key,
            extensions,
        })
    })
}

/// Whether a basicConstraints `extnValue` asserts `cA TRUE`.
pub(super) fn basic_constraints_ca(value: &[u8]) -> Result<bool, CertificateMalformed> {
    AnyRef::from_der(value)?.sequence(|reader: &mut SliceReader<'_>| {
        // DER omits the FALSE default (X.690 clause 11.5), so a present cA is TRUE.
        let ca = !reader.is_finished() && Tag::peek(reader)? == Tag::Boolean;
        if ca && AnyRef::decode(reader)?.value() != [0xff] {
            return Err(CertificateMalformed::BasicConstraintsMalformed);
        }
        if !reader.is_finished() {
            let path_len = AnyRef::decode(reader)?;
            expect_tag(
                path_len,
                Tag::Integer,
                CertificateMalformed::BasicConstraintsMalformed,
            )?;
            // pathLenConstraint is INTEGER (0..MAX) (RFC 5280 §4.2.1.9).
            strict_unsigned(path_len.value())?;
        }
        Ok(ca)
    })
}

/// Whether a keyUsage `extnValue` sets keyCertSign.
pub(super) fn key_usage_cert_sign(value: &[u8]) -> Result<bool, CertificateMalformed> {
    let bits = AnyRef::from_der(value)?;
    expect_tag(
        bits,
        Tag::BitString,
        CertificateMalformed::KeyUsageMalformed,
    )?;
    // A bit past the unused-bits boundary is padding, which `named_bits`
    // requires to be zero, so a set keyCertSign bit is a used bit.
    Ok(named_bits(bits.value())?
        .first()
        .is_some_and(|first| first & KEY_CERT_SIGN != 0))
}

/// Verifies that `issuer` signed `tbs` with `algorithm`.
pub(super) fn verify_signature(
    issuer: &P384PublicKey,
    algorithm: SignatureAlgorithm,
    parts: &CertificateParts<'_>,
) -> Result<(), SignatureFault> {
    let signature = ecdsa_sig_value_der(parts.r, parts.s);
    let result = match algorithm {
        SignatureAlgorithm::EcdsaSha256 => {
            verify_prehash_der_lenient(issuer, &Sha256::digest(parts.tbs), &signature)
        }
        SignatureAlgorithm::EcdsaSha384 => {
            verify_prehash_der_lenient(issuer, &Sha384::digest(parts.tbs), &signature)
        }
        SignatureAlgorithm::Unsupported => return Err(SignatureFault::UnsupportedAlgorithm),
    };
    result.map_err(|_| SignatureFault::DoesNotVerify)
}

/// Reads the content of the single `[n] EXPLICIT OCTET STRING` that a DER
/// `SEQUENCE` extension value holds, the shape of the nonce (`[1]`) and the
/// `aclBlob` (`[3]`).
pub(super) fn explicit_octet_string_in_sequence(
    extension_value: &[u8],
    number: u32,
) -> Result<Vec<u8>, CertificateMalformed> {
    let sequence = AnyRef::from_der(extension_value)?;
    sequence.sequence(|reader: &mut SliceReader<'_>| {
        let tagged = AnyRef::decode(reader)?;
        if !is_context(tagged.tag(), number, true) {
            return Err(CertificateMalformed::UnexpectedElement);
        }
        let octets = AnyRef::from_der(tagged.value())?;
        expect_tag(
            octets,
            Tag::OctetString,
            CertificateMalformed::ElementNotOctets,
        )?;
        Ok(octets.value().to_vec())
    })
}

/// The system name in extension 1.2.840.113635.100.8.7's `[1026]` element,
/// `None` when the element is absent. `Err` when the value is not a DER
/// `SEQUENCE` of context-tagged elements, when `[1026]` repeats, or when
/// `[1026]` does not hold one `OCTET STRING`.
pub(super) fn platform_system_name(
    extension_value: &[u8],
) -> Result<Option<Vec<u8>>, CertificateMalformed> {
    let sequence = AnyRef::from_der(extension_value)?;
    sequence.sequence(|reader: &mut SliceReader<'_>| {
        let mut system = None;
        while !reader.is_finished() {
            let element = AnyRef::decode(reader)?;
            let Tag::ContextSpecific { number, .. } = element.tag() else {
                return Err(CertificateMalformed::PlatformElementUntagged);
            };
            if number.value() != 1026 {
                continue;
            }
            if system.is_some() || !element.tag().is_constructed() {
                return Err(CertificateMalformed::SystemNameRepeatedOrImplicit);
            }
            let octets = AnyRef::from_der(element.value())?;
            expect_tag(
                octets,
                Tag::OctetString,
                CertificateMalformed::ElementNotOctets,
            )?;
            system = Some(octets.value().to_vec());
        }
        Ok(system)
    })
}

#[cfg(test)]
mod tests;
