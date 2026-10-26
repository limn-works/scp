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
//!    crate: the signature algorithm, the validity, the subject key and the
//!    extensions.
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
/// DER content of OID 1.2.840.113635.100.8.2, the App Attest nonce.
pub(super) const OID_APPLE_NONCE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02];
/// DER content of OID 1.2.840.113635.100.8.6, the `aclBlob`.
pub(super) const OID_APPLE_ACL_BLOB: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x06];
/// DER content of OID 1.2.840.113635.100.8.7, the platform extension.
pub(super) const OID_APPLE_PLATFORM: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x07];

/// Length of a SEC1 uncompressed P-256 point.
const P256_POINT_LEN: usize = 65;
/// Length of a SEC1 uncompressed P-384 point.
const P384_POINT_LEN: usize = 97;

/// Why a certificate could not be read. Every value becomes
/// `Rejected{CertificateChainInvalid}` at check 3, or `MalformedToken` and
/// `PlatformUnreported` where checks 5 and 7 read an extension; the text
/// names the defect for debugging only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("certificate malformed: {0}")]
pub(super) struct CertificateMalformed(pub &'static str);

impl From<der::Error> for CertificateMalformed {
    fn from(_: der::Error) -> Self {
        Self("not strict DER")
    }
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

/// Each extension's OID content and `extnValue` content.
pub(super) type Extensions = Vec<(Vec<u8>, Vec<u8>)>;

/// One lenient TLV: its tag byte, the whole TLV, its content, and the bytes
/// after it. Accepts single-byte tags and any definite length form of up to
/// four length bytes, minimal or not. Refuses the indefinite form, because a
/// definite outer length is needed to find the parts.
fn lenient_tlv(input: &[u8]) -> Result<Tlv<'_>, CertificateMalformed> {
    let [tag, first, rest @ ..] = input else {
        return Err(CertificateMalformed("truncated header"));
    };
    if tag & 0x1f == 0x1f {
        return Err(CertificateMalformed("multi-byte tag in outer structure"));
    }
    let (len, rest) = match *first {
        short @ 0x00..=0x7f => (usize::from(short), rest),
        0x80 => return Err(CertificateMalformed("indefinite length")),
        long @ 0x81..=0x84 => {
            let count = usize::from(long & 0x7f);
            let (len_bytes, rest) = rest
                .split_at_checked(count)
                .ok_or(CertificateMalformed("truncated length"))?;
            let len = len_bytes
                .iter()
                .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
            (len, rest)
        }
        _ => return Err(CertificateMalformed("length longer than four bytes")),
    };
    let (content, after) = rest
        .split_at_checked(len)
        .ok_or(CertificateMalformed("content runs past the input"))?;
    let header_len = input.len() - rest.len();
    let whole = input
        .get(..header_len + len)
        .ok_or(CertificateMalformed("content runs past the input"))?;
    Ok((*tag, whole, content, after))
}

/// A lenient non-negative INTEGER's magnitude, leading zero bytes removed.
fn lenient_unsigned(content: &[u8]) -> Result<&[u8], CertificateMalformed> {
    match content.first() {
        None => Err(CertificateMalformed("empty INTEGER")),
        Some(first) if first & 0x80 != 0 => Err(CertificateMalformed("negative INTEGER")),
        Some(_) => {
            let start = content
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(content.len());
            content
                .get(start..)
                .ok_or(CertificateMalformed("empty INTEGER"))
        }
    }
}

/// Splits a certificate's outer `SEQUENCE` leniently (see the module
/// documentation). Bytes after the outer `SEQUENCE`, or after its three
/// parts, are left for [`rebuild_matches`] to reject.
pub(super) fn split_certificate(der: &[u8]) -> Result<CertificateParts<'_>, CertificateMalformed> {
    let (tag, _, body, _) = lenient_tlv(der)?;
    if tag != 0x30 {
        return Err(CertificateMalformed("certificate is not a SEQUENCE"));
    }
    let (tbs_tag, tbs, _, rest) = lenient_tlv(body)?;
    if tbs_tag != 0x30 {
        return Err(CertificateMalformed("tbsCertificate is not a SEQUENCE"));
    }
    let (alg_tag, outer_algorithm, _, rest) = lenient_tlv(rest)?;
    if alg_tag != 0x30 {
        return Err(CertificateMalformed("signatureAlgorithm is not a SEQUENCE"));
    }
    let (bits_tag, _, bits, _) = lenient_tlv(rest)?;
    if bits_tag != 0x03 {
        return Err(CertificateMalformed("signatureValue is not a BIT STRING"));
    }
    let [unused_bits, signature @ ..] = bits else {
        return Err(CertificateMalformed("empty BIT STRING"));
    };
    let (sig_tag, _, sig_body, _) = lenient_tlv(signature)?;
    if sig_tag != 0x30 {
        return Err(CertificateMalformed("ECDSA-Sig-Value is not a SEQUENCE"));
    }
    let (r_tag, _, r, rest) = lenient_tlv(sig_body)?;
    let (s_tag, _, s, _) = lenient_tlv(rest)?;
    if r_tag != 0x02 || s_tag != 0x02 {
        return Err(CertificateMalformed("ECDSA-Sig-Value holds a non-INTEGER"));
    }
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
    /// `validity.notBefore`, Unix seconds.
    pub(super) not_before: u64,
    /// `validity.notAfter`, Unix seconds.
    pub(super) not_after: u64,
    /// The subject public key.
    pub(super) key: SubjectKey,
    /// Each extension's OID content and `extnValue` content. No OID repeats.
    pub(super) extensions: Extensions,
}

impl Tbs {
    /// The `extnValue` content of the extension with this OID.
    pub(super) fn extension(&self, oid: &[u8]) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(candidate, _)| candidate == oid)
            .map(|(_, value)| value.as_slice())
    }
}

fn expect_tag(any: AnyRef<'_>, tag: Tag, what: &'static str) -> Result<(), CertificateMalformed> {
    if any.tag() == tag {
        Ok(())
    } else {
        Err(CertificateMalformed(what))
    }
}

fn is_context(tag: Tag, wanted: u32, wanted_constructed: bool) -> bool {
    matches!(tag, Tag::ContextSpecific { constructed, number }
        if constructed == wanted_constructed && number.value() == wanted)
}

fn time_secs(any: AnyRef<'_>) -> Result<u64, CertificateMalformed> {
    let duration = match any.tag() {
        Tag::UtcTime => any.decode_as::<UtcTime>()?.to_unix_duration(),
        Tag::GeneralizedTime => any.decode_as::<GeneralizedTime>()?.to_unix_duration(),
        _ => return Err(CertificateMalformed("validity time is not a Time")),
    };
    Ok(duration.as_secs())
}

fn parse_signature_algorithm(tlv: &[u8]) -> Result<SignatureAlgorithm, CertificateMalformed> {
    let algorithm = AnyRef::from_der(tlv)?;
    algorithm.sequence(|reader: &mut SliceReader<'_>| {
        let oid = AnyRef::decode(reader)?;
        expect_tag(oid, Tag::ObjectIdentifier, "algorithm is not an OID")?;
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
        expect_tag(bits, Tag::BitString, "subjectPublicKey is not a BIT STRING")?;
        let [0x00, point @ ..] = bits.value() else {
            return Err(CertificateMalformed("subjectPublicKey has unused bits"));
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

fn parse_extensions(wrapper: AnyRef<'_>) -> Result<Extensions, CertificateMalformed> {
    let list = AnyRef::from_der(wrapper.value())?;
    list.sequence(|reader: &mut SliceReader<'_>| {
        let mut extensions: Extensions = Vec::new();
        while !reader.is_finished() {
            let extension = AnyRef::decode(reader)?;
            let (oid, value) = extension.sequence(|inner: &mut SliceReader<'_>| {
                let oid = AnyRef::decode(inner)?;
                expect_tag(oid, Tag::ObjectIdentifier, "extnID is not an OID")?;
                let mut value = AnyRef::decode(inner)?;
                if value.tag() == Tag::Boolean {
                    value = AnyRef::decode(inner)?;
                }
                expect_tag(value, Tag::OctetString, "extnValue is not an OCTET STRING")?;
                Ok::<_, CertificateMalformed>((oid.value().to_vec(), value.value().to_vec()))
            })?;
            if extensions.iter().any(|(seen, _)| *seen == oid) {
                return Err(CertificateMalformed("extension repeated"));
            }
            extensions.push((oid, value));
        }
        Ok(extensions)
    })
}

/// Parses `tbsCertificate` as strict DER (RFC 5280 §4.1).
pub(super) fn parse_tbs(tbs: &[u8]) -> Result<Tbs, CertificateMalformed> {
    let tbs = AnyRef::from_der(tbs)?;
    tbs.sequence(|reader: &mut SliceReader<'_>| {
        if is_context(Tag::peek(reader)?, 0, true) {
            AnyRef::decode(reader)?;
        }
        let serial = AnyRef::decode(reader)?;
        expect_tag(serial, Tag::Integer, "serialNumber is not an INTEGER")?;
        let signature_algorithm_tlv = reader.tlv_bytes()?.to_vec();
        let signature_algorithm = parse_signature_algorithm(&signature_algorithm_tlv)?;
        let issuer = AnyRef::decode(reader)?;
        expect_tag(issuer, Tag::Sequence, "issuer is not a SEQUENCE")?;
        let validity = AnyRef::decode(reader)?;
        let (not_before, not_after) = validity.sequence(|inner: &mut SliceReader<'_>| {
            let not_before = time_secs(AnyRef::decode(inner)?)?;
            let not_after = time_secs(AnyRef::decode(inner)?)?;
            Ok::<_, CertificateMalformed>((not_before, not_after))
        })?;
        let subject = AnyRef::decode(reader)?;
        expect_tag(subject, Tag::Sequence, "subject is not a SEQUENCE")?;
        let key = parse_subject_key(AnyRef::decode(reader)?)?;
        let mut extensions = Vec::new();
        while !reader.is_finished() {
            let field = AnyRef::decode(reader)?;
            if is_context(field.tag(), 3, true) {
                extensions = parse_extensions(field)?;
            } else if !(is_context(field.tag(), 1, false) || is_context(field.tag(), 2, false)) {
                return Err(CertificateMalformed(
                    "unexpected field after subjectPublicKeyInfo",
                ));
            }
        }
        Ok(Tbs {
            signature_algorithm_tlv,
            signature_algorithm,
            not_before,
            not_after,
            key,
            extensions,
        })
    })
}

/// Verifies that `issuer` signed `tbs` with `algorithm`. `false` for an
/// unsupported algorithm or a signature that does not verify.
pub(super) fn verify_signature(
    issuer: &P384PublicKey,
    algorithm: SignatureAlgorithm,
    parts: &CertificateParts<'_>,
) -> bool {
    let signature = ecdsa_sig_value_der(parts.r, parts.s);
    let result = match algorithm {
        SignatureAlgorithm::EcdsaSha256 => {
            verify_prehash_der_lenient(issuer, &Sha256::digest(parts.tbs), &signature)
        }
        SignatureAlgorithm::EcdsaSha384 => {
            verify_prehash_der_lenient(issuer, &Sha384::digest(parts.tbs), &signature)
        }
        SignatureAlgorithm::Unsupported => return false,
    };
    result.is_ok()
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
            return Err(CertificateMalformed("unexpected element"));
        }
        let octets = AnyRef::from_der(tagged.value())?;
        expect_tag(octets, Tag::OctetString, "element is not an OCTET STRING")?;
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
                return Err(CertificateMalformed(
                    "platform element is not context-tagged",
                ));
            };
            if number.value() != 1026 {
                continue;
            }
            if system.is_some() || !element.tag().is_constructed() {
                return Err(CertificateMalformed("[1026] repeated or not explicit"));
            }
            let octets = AnyRef::from_der(element.value())?;
            expect_tag(octets, Tag::OctetString, "[1026] is not an OCTET STRING")?;
            system = Some(octets.value().to_vec());
        }
        Ok(system)
    })
}
