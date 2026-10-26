//! The strict `tbsCertificate` structure §9.3.1 check 3 requires, one row
//! per refusal, and the extension readers check 3 and checks 7 and 8 use.

use super::{
    CertificateMalformed as M, OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, SignatureAlgorithm,
    SubjectKey, basic_constraints_ca, key_usage_cert_sign, parse_tbs, platform_system_name,
};
use crate::trust::device_attestation::test_ca::{
    Alg, BASIC_CONSTRAINTS_CA, BoxResult, Curve, KEY_USAGE_CA, MANY, MANY_BOUND, T0, TestExtension,
    TestResult, explicit, integer, name, octets, oid, platform_extension, seq, spki, tlv, utc_time,
};

/// An unrecognised OID, 1.3.6.1.4.1.99999.1.
const OID_OTHER: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01];

/// A P-256 point of the right length; `parse_tbs` classifies keys and does
/// not check that a point is on the curve.
fn p256_point() -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend([0x11; 64]);
    point
}

fn generalized_time(text: &str) -> Vec<u8> {
    tlv(&[0x18], text.as_bytes())
}

/// The fields of a valid `tbsCertificate`, in order.
struct Fields {
    version: Option<Vec<u8>>,
    serial: Vec<u8>,
    algorithm: Vec<u8>,
    issuer: Vec<u8>,
    validity: Vec<u8>,
    subject: Vec<u8>,
    key: Vec<u8>,
    /// Everything after the key, written as given.
    trailing: Vec<Vec<u8>>,
}

fn extensions_field(extensions: &[TestExtension]) -> Vec<u8> {
    let list: Vec<Vec<u8>> = extensions.iter().map(TestExtension::der).collect();
    let list: Vec<&[u8]> = list.iter().map(Vec::as_slice).collect();
    explicit(3, &seq(&list))
}

impl Fields {
    fn valid() -> BoxResult<Self> {
        Ok(Self {
            version: Some(explicit(0, &integer(&[2]))),
            serial: integer(&[7]),
            algorithm: Alg::Sha384.identifier(),
            issuer: name("Issuer"),
            validity: seq(&[&utc_time(T0)?, &utc_time(T0 + 1)?]),
            subject: name("Subject"),
            key: spki(Curve::P256, &p256_point()),
            trailing: vec![extensions_field(&[TestExtension::critical(
                OID_BASIC_CONSTRAINTS,
                BASIC_CONSTRAINTS_CA.to_vec(),
            )])],
        })
    }

    fn der(&self) -> Vec<u8> {
        let mut parts: Vec<&[u8]> = Vec::new();
        if let Some(version) = &self.version {
            parts.push(version);
        }
        parts.extend([
            self.serial.as_slice(),
            &self.algorithm,
            &self.issuer,
            &self.validity,
            &self.subject,
            &self.key,
        ]);
        parts.extend(self.trailing.iter().map(Vec::as_slice));
        seq(&parts)
    }
}

type FieldsRow = (&'static str, fn(&mut Fields) -> BoxResult<()>, M);

const REFUSALS: [FieldsRow; 18] = [
    (
        "version absent (v1 by default)",
        |f| {
            f.version = None;
            Ok(())
        },
        M::VersionNotV3,
    ),
    (
        "version v1 written",
        |f| {
            f.version = Some(explicit(0, &integer(&[0])));
            Ok(())
        },
        M::VersionNotV3,
    ),
    (
        "version v2",
        |f| {
            f.version = Some(explicit(0, &integer(&[1])));
            Ok(())
        },
        M::VersionNotV3,
    ),
    (
        "version v4",
        |f| {
            f.version = Some(explicit(0, &integer(&[3])));
            Ok(())
        },
        M::VersionNotV3,
    ),
    (
        "serial not an INTEGER",
        |f| {
            f.serial = octets(&[7]);
            Ok(())
        },
        M::SerialNotInteger,
    ),
    (
        "serial INTEGER empty",
        |f| {
            f.serial = tlv(&[0x02], &[]);
            Ok(())
        },
        M::EmptyInteger,
    ),
    (
        "serial with a redundant leading zero",
        |f| {
            f.serial = tlv(&[0x02], &[0x00, 0x07]);
            Ok(())
        },
        M::IntegerNotMinimal,
    ),
    (
        "serial with a redundant leading 0xff",
        |f| {
            f.serial = tlv(&[0x02], &[0xff, 0x80]);
            Ok(())
        },
        M::IntegerNotMinimal,
    ),
    (
        "issuer not a SEQUENCE",
        |f| {
            f.issuer = octets(b"Issuer");
            Ok(())
        },
        M::NameNotSequence,
    ),
    (
        "validity holds an INTEGER",
        |f| {
            f.validity = seq(&[&integer(&[1]), &utc_time(T0)?]);
            Ok(())
        },
        M::TimeNotTime,
    ),
    (
        "GeneralizedTime before 2050",
        |f| {
            f.validity = seq(&[&generalized_time("20270101000000Z"), &utc_time(T0)?]);
            Ok(())
        },
        M::GeneralizedTimeBefore2050,
    ),
    (
        "key BIT STRING with unused bits",
        |f| {
            let mut bits = vec![0x01];
            bits.extend(p256_point());
            f.key = seq(&[
                &seq(&[&oid(super::OID_EC_PUBLIC_KEY), &oid(super::OID_PRIME256V1)]),
                &tlv(&[0x03], &bits),
            ]);
            Ok(())
        },
        M::KeyUnusedBits,
    ),
    (
        "[3] repeated",
        |f| {
            let again = f.trailing.clone();
            f.trailing.extend(again);
            Ok(())
        },
        M::FieldOutOfOrder,
    ),
    (
        "[3] before [1]",
        |f| {
            f.trailing.push(tlv(&[0x81], &[0x00]));
            Ok(())
        },
        M::FieldOutOfOrder,
    ),
    (
        "[2] before [1]",
        |f| {
            f.trailing = vec![tlv(&[0x82], &[0x00]), tlv(&[0x81], &[0x00])];
            Ok(())
        },
        M::FieldOutOfOrder,
    ),
    (
        "[4] after the key",
        |f| {
            f.trailing.push(explicit(4, &integer(&[1])));
            Ok(())
        },
        M::UnexpectedField,
    ),
    (
        "critical written FALSE",
        |f| {
            let extension = seq(&[
                &oid(OID_KEY_USAGE),
                &[0x01, 0x01, 0x00],
                &octets(&KEY_USAGE_CA),
            ]);
            f.trailing = vec![explicit(3, &seq(&[&extension]))];
            Ok(())
        },
        M::CriticalNotTrue,
    ),
    (
        "extensions SEQUENCE empty",
        |f| {
            f.trailing = vec![explicit(3, &seq(&[]))];
            Ok(())
        },
        M::ExtensionsEmpty,
    ),
];

#[test]
fn parse_tbs_refuses_each_shape() -> TestResult {
    let valid = Fields::valid()?;
    assert!(
        parse_tbs(&valid.der()).is_ok(),
        "the unmutated fields parse"
    );
    for (what, mutate, reason) in REFUSALS {
        let mut fields = Fields::valid()?;
        mutate(&mut fields)?;
        assert_eq!(parse_tbs(&fields.der()), Err(reason), "{what}");
    }
    Ok(())
}

#[test]
fn parse_tbs_refuses_a_repeated_extension() -> TestResult {
    let mut fields = Fields::valid()?;
    let extension = TestExtension::plain(OID_OTHER, vec![0x05, 0x00]);
    fields.trailing = vec![extensions_field(&[
        extension.clone(),
        TestExtension::critical(OID_BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_CA.to_vec()),
        extension,
    ])];
    assert_eq!(parse_tbs(&fields.der()), Err(M::ExtensionRepeated));
    Ok(())
}

#[test]
fn parse_tbs_accepts_the_shapes_rfc_5280_allows() -> TestResult {
    // GeneralizedTime from 2050, unique identifiers in order, and no
    // extensions field.
    let mut fields = Fields::valid()?;
    fields.validity = seq(&[
        &generalized_time("20500101000000Z"),
        &generalized_time("20500101000001Z"),
    ]);
    let extensions = fields.trailing.clone();
    fields.trailing = vec![tlv(&[0x81], &[0x00]), tlv(&[0x82], &[0x00])];
    fields.trailing.extend(extensions);
    let tbs = parse_tbs(&fields.der())?;
    assert_eq!(tbs.not_before, 2_524_608_000);
    assert_eq!(tbs.not_after, 2_524_608_001);
    assert_eq!(tbs.signature_algorithm, SignatureAlgorithm::EcdsaSha384);
    assert_eq!(
        tbs.key,
        SubjectKey::P256(p256_point().try_into().map_err(|_| "65 bytes")?)
    );
    assert_eq!(tbs.issuer, name("Issuer"));
    assert_eq!(tbs.subject, name("Subject"));
    assert_eq!(
        tbs.extension(OID_BASIC_CONSTRAINTS),
        Some(BASIC_CONSTRAINTS_CA.as_slice())
    );
    assert!(!tbs.has_unrecognised_critical_extension());

    fields.trailing.clear();
    assert!(parse_tbs(&fields.der())?.extensions.is_empty());
    Ok(())
}

#[test]
fn parse_tbs_classifies_other_keys_and_algorithms() -> TestResult {
    // A 97-byte point under the P-256 curve OID is not a P-384 key.
    let mut point = vec![0x04];
    point.extend([0x22; 96]);
    let mut fields = Fields::valid()?;
    fields.key = spki(Curve::P256, &point);
    fields.algorithm = Alg::Sha512.identifier();
    let tbs = parse_tbs(&fields.der())?;
    assert_eq!(tbs.key, SubjectKey::Other);
    assert_eq!(tbs.signature_algorithm, SignatureAlgorithm::Unsupported);
    // A 65-byte point on prime256v1 under an algorithm other than
    // id-ecPublicKey is not a P-256 key.
    fields.key = seq(&[
        &seq(&[&oid(OID_OTHER), &oid(super::OID_PRIME256V1)]),
        &tlv(&[0x03], &[&[0x00][..], &p256_point()].concat()),
    ]);
    assert_eq!(parse_tbs(&fields.der())?.key, SubjectKey::Other);
    // NULL parameters make a supported OID unsupported.
    fields.algorithm = Alg::Sha256Null.identifier();
    assert_eq!(
        parse_tbs(&fields.der())?.signature_algorithm,
        SignatureAlgorithm::Unsupported
    );
    Ok(())
}

#[test]
fn unrecognised_critical_extension_is_reported() -> TestResult {
    let mut fields = Fields::valid()?;
    fields.trailing = vec![extensions_field(&[TestExtension::critical(
        OID_OTHER,
        vec![0x05, 0x00],
    )])];
    assert!(parse_tbs(&fields.der())?.has_unrecognised_critical_extension());
    // The same extension, not critical, is not reported.
    fields.trailing = vec![extensions_field(&[TestExtension::plain(
        OID_OTHER,
        vec![0x05, 0x00],
    )])];
    assert!(!parse_tbs(&fields.der())?.has_unrecognised_critical_extension());
    Ok(())
}

/// The base-128 content of OID 1.3.6.1.4.1.`n`.
fn numbered_oid(n: u64) -> Vec<u8> {
    let mut arc = Vec::new();
    let mut rest = n;
    arc.push(u8::try_from(rest & 0x7f).unwrap_or_default());
    rest >>= 7;
    while rest > 0 {
        arc.push(0x80 | u8::try_from(rest & 0x7f).unwrap_or_default());
        rest >>= 7;
    }
    arc.reverse();
    let mut content = vec![0x2b, 0x06, 0x01, 0x04, 0x01];
    content.extend(arc);
    content
}

#[test]
fn repeated_extension_check_is_quasilinear() -> TestResult {
    for repeat in [false, true] {
        let mut extensions: Vec<TestExtension> = (0..MANY)
            .map(|n| TestExtension::plain(&numbered_oid(n), vec![0x05, 0x00]))
            .collect();
        if repeat {
            extensions.push(TestExtension::plain(&numbered_oid(0), vec![0x05, 0x00]));
        }
        let mut fields = Fields::valid()?;
        fields.trailing = vec![extensions_field(&extensions)];
        let der = fields.der();
        let started = std::time::Instant::now();
        let parsed = parse_tbs(&der);
        let elapsed = started.elapsed();
        assert!(elapsed < MANY_BOUND, "took {elapsed:?}");
        if repeat {
            assert_eq!(parsed, Err(M::ExtensionRepeated));
        } else {
            assert_eq!(parsed?.extensions.len(), usize::try_from(MANY)?);
        }
    }
    Ok(())
}

#[test]
fn basic_constraints_rows() {
    let rows: [(&[u8], Result<bool, M>); 12] = [
        (&BASIC_CONSTRAINTS_CA, Ok(true)),
        (
            &[0x30, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80],
            Ok(true),
        ),
        (&[0x30, 0x03, 0x02, 0x01, 0x7f], Ok(false)),
        (&[0x30, 0x02, 0x02, 0x00], Err(M::EmptyInteger)),
        (
            &[0x30, 0x04, 0x02, 0x02, 0x00, 0x01],
            Err(M::IntegerNotMinimal),
        ),
        (
            &[0x30, 0x04, 0x02, 0x02, 0xff, 0x80],
            Err(M::IntegerNotMinimal),
        ),
        (&[0x30, 0x03, 0x02, 0x01, 0x80], Err(M::NegativeInteger)),
        (&[0x30, 0x03, 0x01, 0x01, 0xff], Ok(true)),
        (&[0x30, 0x00], Ok(false)),
        (&[0x30, 0x03, 0x02, 0x01, 0x00], Ok(false)),
        (
            &[0x30, 0x03, 0x01, 0x01, 0x00],
            Err(M::BasicConstraintsMalformed),
        ),
        (
            &[0x30, 0x03, 0x04, 0x01, 0x00],
            Err(M::BasicConstraintsMalformed),
        ),
    ];
    for (value, expected) in rows {
        assert_eq!(basic_constraints_ca(value), expected, "{value:02x?}");
    }
}

#[test]
fn key_usage_rows() {
    let rows: [(&[u8], Result<bool, M>); 15] = [
        (&KEY_USAGE_CA, Ok(true)),
        (&[0x03, 0x02, 0x02, 0x04], Ok(true)),
        (&[0x03, 0x03, 0x07, 0x04, 0x80], Ok(true)),
        (&[0x03, 0x02, 0x07, 0x80], Ok(false)),
        (&[0x03, 0x03, 0x07, 0x00, 0x80], Ok(false)),
        (&[0x03, 0x01, 0x00], Ok(false)),
        (&[0x04, 0x01, 0x06], Err(M::KeyUsageMalformed)),
        (&[0x03, 0x00], Err(M::KeyUsageMalformed)),
        // keyCertSign (bit 5) sits in the 3 declared padding bits.
        (&[0x03, 0x02, 0x03, 0x04], Err(M::BitStringPaddingNotZero)),
        (&[0x03, 0x02, 0x01, 0x05], Err(M::BitStringPaddingNotZero)),
        (
            &[0x03, 0x02, 0x08, 0x04],
            Err(M::BitStringUnusedBitsInvalid),
        ),
        (
            &[0x03, 0x02, 0xff, 0x04],
            Err(M::BitStringUnusedBitsInvalid),
        ),
        (&[0x03, 0x01, 0x01], Err(M::BitStringUnusedBitsInvalid)),
        (&[0x03, 0x02, 0x00, 0x04], Err(M::BitStringTrailingZeroBit)),
        (
            &[0x03, 0x03, 0x00, 0x04, 0x00],
            Err(M::BitStringTrailingZeroBit),
        ),
    ];
    for (value, expected) in rows {
        assert_eq!(key_usage_cert_sign(value), expected, "{value:02x?}");
    }
}

#[test]
fn platform_system_name_rows() {
    let repeated = seq(&[
        &tlv(&[0xbf, 0x88, 0x02], &octets(b"iOS")),
        &tlv(&[0xbf, 0x88, 0x02], &octets(b"iOS")),
    ]);
    let primitive = seq(&[&tlv(&[0x9f, 0x88, 0x02], b"iOS")]);
    let untagged = seq(&[&octets(b"iOS")]);
    let other_element = seq(&[&tlv(&[0xbf, 0x88, 0x03], &octets(b"x"))]);
    assert_eq!(
        platform_system_name(&platform_extension(b"iOS")),
        Ok(Some(b"iOS".to_vec()))
    );
    assert_eq!(platform_system_name(&other_element), Ok(None));
    assert_eq!(
        platform_system_name(&repeated),
        Err(M::SystemNameRepeatedOrImplicit)
    );
    assert_eq!(
        platform_system_name(&primitive),
        Err(M::SystemNameRepeatedOrImplicit)
    );
    assert_eq!(
        platform_system_name(&untagged),
        Err(M::PlatformElementUntagged)
    );
}
