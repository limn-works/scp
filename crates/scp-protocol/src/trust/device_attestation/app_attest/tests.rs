//! App Attest checks 1 through 12 (`09-security-model.md` §9.3.1).
//!
//! Every rejection runs through [`rejection_case`], which first reads the
//! unmutated fixture as `Verified`, then asserts the mutation's cause and the
//! check that stopped the run, then reruns without that check and asserts the
//! cause is gone. [`rejection_cases!`] generates each case's test and the
//! list the meta-test reads, so a case cannot be counted without existing.

use scp_crypto::p256::P256SecretKey;
use scp_crypto::p384::{self, P384SecretKey};
use scp_did::Identifier;
use sha2::{Digest, Sha256};

use super::{
    APP_ATTEST_CHECKS, APPLE_APP_ATTESTATION_ROOT, AppAttestCheck, AppAttestRead, AppAttestRoot,
    CheckFn, Run, Stop, choose_platform_path, lenient_object, read_app_attest, read_with_root, run,
};
use crate::trust::device_attestation::test_ca::{
    AAGUID_DEVELOPMENT, Alg, BoxResult, Built, CredentialId, Curve, DAY, Fixture, Issued,
    MACOS_ACL_BLOB, MAX_AGE_SECS, Nonce, T0, TestResult, acl_blob_extension, attestation_object,
    cbor_array, cbor_bytes, cbor_head, cbor_map, cbor_text, explicit, extensions_with_category,
    nonce_extension, octets, platform_extension, policy_for, seq, tlv,
};
use crate::trust::device_attestation::{
    AppAttestObjectError, DeviceAttestationPlatform, DeviceAttestationRejection as R,
    canonicalize_app_attest_object, device_attestation_binding_digest, x509,
};
use crate::trust::sybil::{AcceptedAppId, ApplePlatform};

// ── Harness ─────────────────────────────────────────────────────────────────

/// Every check except `check`.
fn without(check: AppAttestCheck) -> Vec<(AppAttestCheck, CheckFn)> {
    APP_ATTEST_CHECKS
        .iter()
        .filter(|(id, _)| *id != check)
        .copied()
        .collect()
}

fn require_verified(run: &Run, what: &str) -> TestResult {
    match &run.result {
        Ok(_) => Ok(()),
        Err(stop) => Err(format!(
            "{what}: expected Verified, got {stop:?} after {:?}",
            run.ran
        )
        .into()),
    }
}

/// The four steps of every rejection test.
fn rejection_case(mutate: fn(&mut Fixture), check: AppAttestCheck, cause: R) -> TestResult {
    let mut fixture = Fixture::valid();
    require_verified(&fixture.run_all()?, "unmutated fixture")?;
    mutate(&mut fixture);
    let full = fixture.run_all()?;
    assert_eq!(full.result, Err(Stop::Reject(cause)), "ran {:?}", full.ran);
    assert_eq!(
        full.ran.last(),
        Some(&check),
        "the named check stopped the run"
    );
    let rerun = fixture.run(&without(check))?;
    assert_ne!(
        rerun.result,
        Err(Stop::Reject(cause)),
        "without {check:?} the cause must be gone; ran {:?}",
        rerun.ran
    );
    Ok(())
}

/// A must-pass case: the mutated fixture still reads `Verified`.
fn passes(mutate: fn(&mut Fixture)) -> TestResult {
    let mut fixture = Fixture::valid();
    mutate(&mut fixture);
    require_verified(&fixture.run_all()?, "must-pass case")
}

macro_rules! rejection_cases {
    ($($name:ident: $check:ident => $cause:ident, $mutate:expr;)+) => {
        $(
            #[test]
            fn $name() -> TestResult {
                rejection_case($mutate, AppAttestCheck::$check, R::$cause)
            }
        )+
        /// The check each generated case names, one entry per case.
        const COVERED_CHECKS: &[AppAttestCheck] = &[$(AppAttestCheck::$check),+];
    };
}

#[test]
fn every_check_has_a_rejection_case() {
    for check in AppAttestCheck::ALL {
        assert!(
            COVERED_CHECKS.contains(&check),
            "{check:?} has no rejection case"
        );
    }
    let listed: Vec<AppAttestCheck> = APP_ATTEST_CHECKS.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        listed,
        AppAttestCheck::ALL,
        "the array runs every check once, in order"
    );
}

// ── Object hooks (check 1) ──────────────────────────────────────────────────

fn x5c(built: &Built) -> Vec<u8> {
    cbor_array(&[cbor_bytes(&built.leaf), cbor_bytes(&built.intermediate)])
}

fn fmt_pair() -> (Vec<u8>, Vec<u8>) {
    (cbor_text("fmt"), cbor_text("apple-appattest"))
}

fn statement_pair(built: &Built) -> (Vec<u8>, Vec<u8>) {
    (
        cbor_text("attStmt"),
        cbor_map(&[(cbor_text("x5c"), x5c(built))]),
    )
}

fn auth_data_pair(built: &Built) -> (Vec<u8>, Vec<u8>) {
    (cbor_text("authData"), cbor_bytes(&built.auth_data))
}

/// A map head with a one-byte argument where the immediate form fits.
fn long_map_head(count: u8) -> Vec<u8> {
    vec![0xb8, count]
}

fn extra_top_level_key(built: &Built) -> Vec<u8> {
    // "zzz" sorts between "fmt" and "attStmt", so the map stays canonical.
    cbor_map(&[
        fmt_pair(),
        (cbor_text("zzz"), cbor_head(0, 0)),
        statement_pair(built),
        auth_data_pair(built),
    ])
}

fn statement_with_receipt(built: &Built, receipt: Vec<u8>) -> Vec<u8> {
    cbor_map(&[
        fmt_pair(),
        (
            cbor_text("attStmt"),
            cbor_map(&[
                (cbor_text("x5c"), x5c(built)),
                (cbor_text("receipt"), receipt),
            ]),
        ),
        auth_data_pair(built),
    ])
}

fn tagged_receipt(built: &Built) -> Vec<u8> {
    let mut receipt = cbor_head(6, 24);
    receipt.extend(cbor_bytes(b"receipt"));
    statement_with_receipt(built, receipt)
}

fn byte_string_receipt(built: &Built) -> Vec<u8> {
    statement_with_receipt(built, cbor_bytes(b"receipt"))
}

fn x5c_one_element(built: &Built) -> Vec<u8> {
    cbor_map(&[
        fmt_pair(),
        (
            cbor_text("attStmt"),
            cbor_map(&[(cbor_text("x5c"), cbor_array(&[cbor_bytes(&built.leaf)]))]),
        ),
        auth_data_pair(built),
    ])
}

fn tagged_x5c_element(built: &Built) -> Vec<u8> {
    let mut leaf = cbor_head(6, 24);
    leaf.extend(cbor_bytes(&built.leaf));
    cbor_map(&[
        fmt_pair(),
        (
            cbor_text("attStmt"),
            cbor_map(&[(
                cbor_text("x5c"),
                cbor_array(&[leaf, cbor_bytes(&built.intermediate)]),
            )]),
        ),
        auth_data_pair(built),
    ])
}

fn indefinite_auth_data(built: &Built) -> Vec<u8> {
    let (first, second) = built.auth_data.split_at(built.auth_data.len() / 2);
    let mut value = vec![0x5f];
    value.extend(cbor_bytes(first));
    value.extend(cbor_bytes(second));
    value.push(0xff);
    cbor_map(&[
        fmt_pair(),
        statement_pair(built),
        (cbor_text("authData"), value),
    ])
}

fn auth_data_twice_valid_first(built: &Built) -> Vec<u8> {
    cbor_map(&[
        fmt_pair(),
        statement_pair(built),
        auth_data_pair(built),
        (cbor_text("authData"), cbor_bytes(&[0u8; 10])),
    ])
}

fn auth_data_twice_valid_second(built: &Built) -> Vec<u8> {
    cbor_map(&[
        fmt_pair(),
        statement_pair(built),
        (cbor_text("authData"), cbor_bytes(&[0u8; 10])),
        auth_data_pair(built),
    ])
}

fn top_level_out_of_order(built: &Built) -> Vec<u8> {
    cbor_map(&[auth_data_pair(built), fmt_pair(), statement_pair(built)])
}

fn statement_out_of_order(built: &Built) -> Vec<u8> {
    cbor_map(&[
        fmt_pair(),
        (
            cbor_text("attStmt"),
            cbor_map(&[
                (cbor_text("receipt"), cbor_bytes(b"r")),
                (cbor_text("x5c"), x5c(built)),
            ]),
        ),
        auth_data_pair(built),
    ])
}

fn long_top_level_head(built: &Built) -> Vec<u8> {
    let mut out = long_map_head(3);
    for (key, value) in [fmt_pair(), statement_pair(built), auth_data_pair(built)] {
        out.extend(key);
        out.extend(value);
    }
    out
}

fn long_statement_head(built: &Built) -> Vec<u8> {
    let mut statement = long_map_head(1);
    statement.extend(cbor_text("x5c"));
    statement.extend(x5c(built));
    cbor_map(&[
        fmt_pair(),
        (cbor_text("attStmt"), statement),
        auth_data_pair(built),
    ])
}

fn long_x5c_array_head(built: &Built) -> Vec<u8> {
    let mut array = vec![0x98, 0x02];
    array.extend(cbor_bytes(&built.leaf));
    array.extend(cbor_bytes(&built.intermediate));
    cbor_map(&[
        fmt_pair(),
        (cbor_text("attStmt"), cbor_map(&[(cbor_text("x5c"), array)])),
        auth_data_pair(built),
    ])
}

fn long_x5c_byte_string_head(built: &Built) -> Vec<u8> {
    // A four-byte length where the two-byte form fits.
    let mut leaf = vec![0x5a];
    leaf.extend_from_slice(&u32::try_from(built.leaf.len()).unwrap_or(0).to_be_bytes());
    leaf.extend_from_slice(&built.leaf);
    let mut array = cbor_head(4, 2);
    array.extend(leaf);
    array.extend(cbor_bytes(&built.intermediate));
    cbor_map(&[
        fmt_pair(),
        (cbor_text("attStmt"), cbor_map(&[(cbor_text("x5c"), array)])),
        auth_data_pair(built),
    ])
}

fn repeated_x5c_key(built: &Built) -> Vec<u8> {
    cbor_map(&[
        fmt_pair(),
        (
            cbor_text("attStmt"),
            cbor_map(&[
                (cbor_text("x5c"), x5c(built)),
                (cbor_text("x5c"), x5c(built)),
            ]),
        ),
        auth_data_pair(built),
    ])
}

// ── authData hooks (check 2) ────────────────────────────────────────────────

fn truncate_to_54(auth_data: &mut Vec<u8>) {
    auth_data.truncate(54);
}

fn truncate_inside_credential_id(auth_data: &mut Vec<u8>) {
    auth_data.truncate(55 + 32 - 1);
}

// ── Certificate hooks (check 3) ─────────────────────────────────────────────

/// The leaf with its outer `signatureAlgorithm` length in long form.
fn long_form_algorithm_length(issued: &Issued) -> Vec<u8> {
    let content = issued.outer_alg.get(2..).unwrap_or_default();
    let mut algorithm = vec![0x30, 0x81, u8::try_from(content.len()).unwrap_or(0)];
    algorithm.extend_from_slice(content);
    let mut bits = vec![issued.unused_bits];
    bits.extend_from_slice(&issued.signature);
    seq(&[&issued.tbs, &algorithm, &tlv(&[0x03], &bits)])
}

/// The leaf with its signature `BIT STRING` length as `0x82 0x00 nn`.
fn padded_signature_length(issued: &Issued) -> Vec<u8> {
    let mut bits = vec![issued.unused_bits];
    bits.extend_from_slice(&issued.signature);
    let mut field = vec![0x03, 0x82, 0x00, u8::try_from(bits.len()).unwrap_or(0)];
    field.extend(bits);
    seq(&[&issued.tbs, &issued.outer_alg, &field])
}

/// Each mutation that changes only bytes outside `tbsCertificate`, or sets an
/// algorithm check 3 refuses, with the leaf's signature left valid.
type Mutation = fn(&mut Fixture);

const LEAF_CHAIN_MUTATIONS: [(&str, Mutation); 8] = [
    ("long-form outer length", |f| {
        f.leaf_hook = Some(long_form_algorithm_length);
    }),
    ("0x82 0x00 nn length", |f| {
        f.leaf_hook = Some(padded_signature_length);
    }),
    ("NULL outer parameters", |f| {
        f.leaf.outer_alg = Alg::Sha256Null;
    }),
    ("nonzero unused bits", |f| f.leaf.unused_bits = 1),
    ("outer algorithm differs from inner", |f| {
        f.leaf.outer_alg = Alg::Sha384;
    }),
    ("inner ecdsa-with-SHA512", |f| {
        f.leaf.inner_alg = Alg::Sha512;
        f.leaf.outer_alg = Alg::Sha512;
    }),
    ("inner ecdsa-with-SHA256 with NULL", |f| {
        f.leaf.inner_alg = Alg::Sha256Null;
        f.leaf.outer_alg = Alg::Sha256Null;
    }),
    ("inner RSA", |f| {
        f.leaf.inner_alg = Alg::Rsa;
        f.leaf.outer_alg = Alg::Rsa;
    }),
];

fn intermediate_public_key(fixture: &Fixture) -> BoxResult<p384::P384PublicKey> {
    Ok(P384SecretKey::from_seed(&fixture.intermediate_seed)?.public_key()?)
}

#[test]
fn leaf_chain_mutations_keep_a_valid_signature_and_fail_check_3() -> TestResult {
    for (what, mutate) in LEAF_CHAIN_MUTATIONS {
        let mut fixture = Fixture::valid();
        mutate(&mut fixture);
        let built = fixture.build()?;
        let issuer = intermediate_public_key(&fixture)?;
        p384::verify_prehash_der_lenient(
            &issuer,
            &built.leaf_issued.digest,
            &built.leaf_issued.signature,
        )
        .map_err(|error| format!("{what}: signature must verify: {error}"))?;
        rejection_case(
            mutate,
            AppAttestCheck::CertificateChain,
            R::CertificateChainInvalid,
        )
        .map_err(|error| format!("{what}: {error}"))?;
    }
    Ok(())
}

#[test]
fn rebuild_comparison_runs_separately_from_signature_check() -> TestResult {
    let mut fixture = Fixture::valid();
    fixture.leaf_hook = Some(long_form_algorithm_length);
    let built = fixture.build()?;
    let parts = x509::split_certificate(&built.leaf)?;
    let tbs = x509::parse_tbs(parts.tbs)?;
    let issuer = intermediate_public_key(&fixture)?;
    assert!(x509::verify_signature(
        &issuer,
        tbs.signature_algorithm,
        &parts
    ));
    assert!(!x509::rebuild_matches(
        &built.leaf,
        &parts,
        &tbs.signature_algorithm_tlv
    ));
    // The unmutated leaf passes both.
    let clean = Fixture::valid().build()?;
    let parts = x509::split_certificate(&clean.leaf)?;
    let tbs = x509::parse_tbs(parts.tbs)?;
    assert!(x509::verify_signature(
        &issuer,
        tbs.signature_algorithm,
        &parts
    ));
    assert!(x509::rebuild_matches(
        &clean.leaf,
        &parts,
        &tbs.signature_algorithm_tlv
    ));
    Ok(())
}

// ── The rejection cases ─────────────────────────────────────────────────────

fn other_identifier_digest(
    fixture: &Fixture,
    identifier: &str,
    context: &str,
) -> BoxResult<[u8; 32]> {
    let identifier = Identifier::from_bytes(Sha256::digest(identifier.as_bytes()).into());
    Ok(device_attestation_binding_digest(
        &identifier,
        context,
        &fixture.policy.device_attestation_challenge,
    )?)
}

fn bundle_and_category(version: Vec<u8>) -> Vec<u8> {
    // "apple_bundle_version_01" (23 bytes) sorts before
    // "apple_validation_category_01" (28 bytes).
    cbor_map(&[
        (cbor_text("apple_bundle_version_01"), version),
        (
            cbor_text("apple_validation_category_01"),
            cbor_bytes(&4u32.to_le_bytes()),
        ),
    ])
}

fn accept_bundle_versions(fixture: &mut Fixture, versions: &[&str]) {
    for accepted in &mut fixture.policy.accepted_app_ids {
        accepted.accepted_bundle_versions = versions.iter().map(|v| (*v).to_owned()).collect();
    }
}

fn mac(fixture: &mut Fixture) {
    *fixture = Fixture::valid_mac();
}

rejection_cases! {
    // AC15: keys and types.
    extra_top_level_key_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(extra_top_level_key);
    tagged_receipt_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(tagged_receipt);
    x5c_with_one_element_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(x5c_one_element);
    tagged_x5c_element_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(tagged_x5c_element);
    // AC16: canonical encoding.
    indefinite_length_auth_data_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(indefinite_auth_data);
    auth_data_twice_valid_first_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(auth_data_twice_valid_first);
    auth_data_twice_valid_second_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(auth_data_twice_valid_second);
    top_level_key_order_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(top_level_out_of_order);
    statement_key_order_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(statement_out_of_order);
    long_top_level_map_head_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(long_top_level_head);
    long_statement_map_head_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(long_statement_head);
    long_x5c_array_head_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(long_x5c_array_head);
    long_x5c_byte_string_head_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(long_x5c_byte_string_head);
    repeated_x5c_key_malformed: ObjectEncoding => MalformedToken,
        |f| f.object_hook = Some(repeated_x5c_key);
    // AC17: offsets.
    auth_data_54_bytes_truncated: AuthData => AuthDataTruncated,
        |f| f.auth_data_hook = Some(truncate_to_54);
    credential_id_length_31_invalid: AuthData => CredentialIdLengthInvalid,
        |f| f.credential_id_length = Some(31);
    auth_data_ends_inside_credential_id_truncated: AuthData => AuthDataTruncated,
        |f| f.auth_data_hook = Some(truncate_inside_credential_id);
    // AC18: COSE key and extensions.
    truncated_cose_key_malformed: AuthData => MalformedToken,
        |f| {
            f.extensions = None;
            f.cose_key = Some(vec![0xa5, 0x01, 0x02, 0x03]);
        };
    truncated_extensions_map_malformed: AuthData => MalformedToken,
        |f| f.extensions = Some(vec![0xa1, 0x61]);
    extensions_not_a_map_malformed: AuthData => MalformedToken,
        |f| f.extensions = Some(cbor_array(&[cbor_head(0, 1)]));
    // A repeated key that checks 11 and 12 never read, so only check 2 can
    // see it; `extension` refuses a repeat of a key it reads as well.
    extensions_repeated_key_malformed: AuthData => MalformedToken,
        |f| {
            f.extensions = Some(cbor_map(&[
                (cbor_text("other"), cbor_head(0, 1)),
                (cbor_text("other"), cbor_head(0, 2)),
            ]));
        };
    extensions_trailing_bytes_malformed: AuthData => MalformedToken,
        |f| {
            let mut extensions = extensions_with_category(&4u32.to_le_bytes());
            extensions.push(0x00);
            f.extensions = Some(extensions);
        };
    // AC19: the chain.
    chain_to_foreign_root_invalid: CertificateChain => CertificateChainInvalid,
        |f| f.anchor_seed = Some([0x09; 32]);
    leaf_not_before_now_plus_301_invalid: CertificateChain => CertificateChainInvalid,
        |f| f.now_secs = T0 - 301;
    intermediate_ends_before_leaf_not_before_invalid: CertificateChain => CertificateChainInvalid,
        |f| f.intermediate.not_after = T0 - 1;
    intermediate_starts_after_leaf_not_before_invalid: CertificateChain => CertificateChainInvalid,
        |f| f.intermediate.not_before = T0 + 1;
    root_ends_before_leaf_not_before_invalid: CertificateChain => CertificateChainInvalid,
        |f| f.root.not_after = T0 - 1;
    leaf_not_before_after_its_not_after_invalid: CertificateChain => CertificateChainInvalid,
        |f| f.leaf.not_after = T0 - 1;
    // Curves at the root, x5c[1] and the leaf.
    root_key_p256_invalid: CertificateChain => CertificateChainInvalid,
        |f| f.root.curve_override = Some(Curve::P256);
    intermediate_key_p256_invalid: CertificateChain => CertificateChainInvalid,
        |f| f.intermediate.curve_override = Some(Curve::P256);
    leaf_key_p384_invalid: CertificateChain => CertificateChainInvalid,
        |f| f.leaf.curve_override = Some(Curve::P384);
    // The intermediate's algorithm is read from its own tbsCertificate.
    intermediate_inner_sha512_invalid: CertificateChain => CertificateChainInvalid,
        |f| {
            f.intermediate.inner_alg = Alg::Sha512;
            f.intermediate.outer_alg = Alg::Sha512;
        };
    intermediate_outer_differs_invalid: CertificateChain => CertificateChainInvalid,
        |f| f.intermediate.outer_alg = Alg::Sha256;
    // AC21: maximum age.
    app_attest_expired: MaxAge => Expired,
        |f| f.now_secs = T0 + MAX_AGE_SECS + 1;
    // AC22 and B2: the nonce.
    missing_8_2_malformed_token: Nonce => MalformedToken,
        |f| f.nonce = Nonce::Absent;
    nonce_31_bytes_malformed_token: Nonce => MalformedToken,
        |f| f.nonce = Nonce::Raw(nonce_extension(&[0u8; 31]));
    nonce_wrong_tag_malformed_token: Nonce => MalformedToken,
        |f| f.nonce = Nonce::Raw(seq(&[&explicit(2, &octets(&[0u8; 32]))]));
    nonce_binds_identifier: Nonce => NonceMismatch,
        |f| {
            if let Ok(digest) = other_identifier_digest(f, "identifier X", "ctx-1") {
                f.binding_digest = other_identifier_digest(f, "identifier Y", "ctx-1").unwrap_or([0; 32]);
                f.nonce = Nonce::ForDigest(digest);
            }
        };
    nonce_binds_context: Nonce => NonceMismatch,
        |f| {
            if let Ok(digest) = other_identifier_digest(f, "identifier X", "ctx-X") {
                f.binding_digest = other_identifier_digest(f, "identifier X", "ctx-Y").unwrap_or([0; 32]);
                f.nonce = Nonce::ForDigest(digest);
            }
        };
    // AC24 and B1: the key ID.
    hybrid_chain_a_cred_id_b_key_id_mismatch: KeyId => KeyIdMismatch,
        |f| {
            if let Ok(key) = P256SecretKey::from_scalar_bytes(&[0x04; 32]) {
                f.credential_id = CredentialId::Raw(Sha256::digest(key.public_key().to_uncompressed()).to_vec());
            }
        };
    // AC25: the path.
    watchos_without_8_6_platform_unreported: PlatformPath => PlatformUnreported,
        |f| f.platform = Some(platform_extension(b"watchos"));
    malformed_8_7_platform_unreported: PlatformPath => PlatformUnreported,
        |f| f.platform = Some(vec![0x04, 0x01, 0x00]);
    // AC29 and B3: the aclBlob.
    mac_missing_8_6: AclBlob => AclBlobMismatch,
        |f| {
            mac(f);
            f.acl_blob = None;
        };
    mac_wrong_acl_blob: AclBlob => AclBlobMismatch,
        |f| {
            mac(f);
            f.acl_blob = Some(acl_blob_extension(&[0u8; 66]));
        };
    mac_acl_blob_wrong_tag: AclBlob => AclBlobMismatch,
        |f| {
            mac(f);
            f.acl_blob = Some(seq(&[&explicit(2, &octets(&MACOS_ACL_BLOB))]));
        };
    leaf_with_8_6_takes_macos_path: AclBlob => AclBlobMismatch,
        |f| f.acl_blob = Some(vec![0x05, 0x00]);
    // AC28: the App ID.
    rp_id_hash_unmatched: AppId => AppIdNotAccepted,
        |f| f.rp_id = "TEAMID1234.org.example.other".to_owned();
    empty_app_id_list: AppId => AppIdNotAccepted,
        |f| f.policy.accepted_app_ids.clear();
    platform_mismatch: AppId => PlatformMismatch,
        |f| f.policy = policy_for(ApplePlatform::MacOs);
    mac_attestation_against_ios_label: AppId => PlatformMismatch,
        |f| {
            mac(f);
            f.policy = policy_for(ApplePlatform::Ios);
        };
    // AC26.
    nonzero_counter: Counter => CounterNotZero,
        |f| f.counter = 1;
    // AC27.
    develop_aaguid: Aaguid => DevelopmentEnvironment,
        |f| f.aaguid = AAGUID_DEVELOPMENT;
    other_aaguid_malformed: Aaguid => MalformedToken,
        |f| f.aaguid = *b"appattestother\0\0";
    // AC30: the validation category.
    category_three_bytes_malformed: ValidationCategory => MalformedToken,
        |f| f.extensions = Some(extensions_with_category(&[4, 0, 0]));
    category_text_malformed: ValidationCategory => MalformedToken,
        |f| f.extensions = Some(cbor_map(&[(cbor_text("apple_validation_category_01"), cbor_text("4"))]));
    category_0_rejected: ValidationCategory => ValidationCategoryNotAccepted,
        |f| {
            f.policy.accepted_validation_categories = vec![0, 4];
            f.extensions = Some(extensions_with_category(&0u32.to_le_bytes()));
        };
    category_7_rejected: ValidationCategory => ValidationCategoryNotAccepted,
        |f| {
            f.policy.accepted_validation_categories = vec![7, 4];
            f.extensions = Some(extensions_with_category(&7u32.to_le_bytes()));
        };
    category_8_rejected: ValidationCategory => ValidationCategoryNotAccepted,
        |f| {
            f.policy.accepted_validation_categories = vec![8, 4];
            f.extensions = Some(extensions_with_category(&8u32.to_le_bytes()));
        };
    category_9_rejected: ValidationCategory => ValidationCategoryNotAccepted,
        |f| {
            f.policy.accepted_validation_categories = vec![9, 4];
            f.extensions = Some(extensions_with_category(&9u32.to_le_bytes()));
        };
    category_5_not_accepted: ValidationCategory => ValidationCategoryNotAccepted,
        |f| f.extensions = Some(extensions_with_category(&5u32.to_le_bytes()));
    category_4_outside_non_empty_list: ValidationCategory => ValidationCategoryNotAccepted,
        |f| f.policy.accepted_validation_categories = vec![5];
    category_absent_on_macos: ValidationCategory => ValidationCategoryNotAccepted,
        |f| {
            mac(f);
            f.extensions = None;
        };
    category_absent_on_ios_with_flag_set: ValidationCategory => ValidationCategoryNotAccepted,
        |f| {
            f.extensions = None;
            f.policy.require_validation_category = true;
        };
    // AC31: the bundle version.
    bundle_version_byte_string_malformed: BundleVersion => MalformedToken,
        |f| f.extensions = Some(bundle_and_category(cbor_bytes(b"1.0")));
    bundle_version_outside_list: BundleVersion => BundleVersionNotAccepted,
        |f| {
            accept_bundle_versions(f, &["2.0"]);
            f.extensions = Some(bundle_and_category(cbor_text("1.0")));
        };
    bundle_version_absent_with_non_empty_list: BundleVersion => BundleVersionNotAccepted,
        |f| accept_bundle_versions(f, &["1.0"]);
}

// ── Must-pass cases ─────────────────────────────────────────────────────────

#[test]
fn statement_without_receipt_passes() -> TestResult {
    let fixture = Fixture::valid();
    let built = fixture.build()?;
    // The valid fixture's attStmt holds x5c alone.
    assert_eq!(
        built.object,
        attestation_object(&built.auth_data, &built.leaf, &built.intermediate)
    );
    passes(|_| {})
}

#[test]
fn statement_with_byte_string_receipt_passes() -> TestResult {
    passes(|f| f.object_hook = Some(byte_string_receipt))
}

#[test]
fn non_canonical_extensions_map_passes() -> TestResult {
    passes(|f| {
        // Category key before bundle key: not RFC 8949 §4.2.1 order.
        f.extensions = Some(cbor_map(&[
            (
                cbor_text("apple_validation_category_01"),
                cbor_bytes(&4u32.to_le_bytes()),
            ),
            (cbor_text("apple_bundle_version_01"), cbor_text("1.0")),
        ]));
    })
}

#[test]
fn extensions_found_with_ed_bit_clear() -> TestResult {
    // With the flag set, an absent category fails; the run passes only if the
    // reader finds the extensions although the ED flag is clear.
    passes(|f| {
        f.flags = 0x40;
        f.policy.require_validation_category = true;
    })
}

#[test]
fn leaf_not_before_now_plus_300_passes() -> TestResult {
    passes(|f| f.now_secs = T0 - 300)
}

#[test]
fn intermediate_not_before_equal_to_leaf_not_before_passes() -> TestResult {
    passes(|f| f.intermediate.not_before = T0)
}

#[test]
fn certificates_valid_at_leaf_not_before_after_their_not_after_pass() -> TestResult {
    // Validity is read at the leaf's notBefore, not at the reader's time.
    passes(|f| f.now_secs = T0 + 20 * DAY)
}

#[test]
fn app_attest_at_max_age_passes() -> TestResult {
    passes(|f| f.now_secs = T0 + MAX_AGE_SECS)
}

#[test]
fn sha256_signed_leaf_verifies() -> TestResult {
    let fixture = Fixture::valid();
    assert_eq!(fixture.leaf.inner_alg, Alg::Sha256);
    let built = fixture.build()?;
    assert_eq!(
        x509::parse_tbs(x509::split_certificate(&built.leaf)?.tbs)?.signature_algorithm,
        x509::SignatureAlgorithm::EcdsaSha256
    );
    require_verified(&fixture.run_all()?, "SHA-256 leaf")?;
    passes(|f| {
        f.intermediate.inner_alg = Alg::Sha256;
        f.intermediate.outer_alg = Alg::Sha256;
    })
}

#[test]
fn sha384_signed_intermediate_verifies() -> TestResult {
    let fixture = Fixture::valid();
    assert_eq!(fixture.intermediate.inner_alg, Alg::Sha384);
    let built = fixture.build()?;
    assert_eq!(
        x509::parse_tbs(x509::split_certificate(&built.intermediate)?.tbs)?.signature_algorithm,
        x509::SignatureAlgorithm::EcdsaSha384
    );
    require_verified(&fixture.run_all()?, "SHA-384 intermediate")?;
    passes(|f| {
        f.leaf.inner_alg = Alg::Sha384;
        f.leaf.outer_alg = Alg::Sha384;
    })
}

#[test]
fn high_s_chain_verifies() -> TestResult {
    let mut fixture = Fixture::valid();
    let low = fixture.build()?;
    fixture.leaf.high_s = true;
    fixture.intermediate.high_s = true;
    let high = fixture.build()?;
    assert_ne!(low.leaf_issued.signature, high.leaf_issued.signature);
    assert_ne!(
        low.intermediate_issued.signature,
        high.intermediate_issued.signature
    );
    require_verified(&fixture.run_all()?, "high-s chain")
}

#[test]
fn category_4_with_empty_list_passes() -> TestResult {
    let fixture = Fixture::valid();
    assert!(fixture.policy.accepted_validation_categories.is_empty());
    passes(|_| {})
}

#[test]
fn category_5_in_list_passes() -> TestResult {
    passes(|f| {
        f.policy.accepted_validation_categories = vec![5];
        f.extensions = Some(extensions_with_category(&5u32.to_le_bytes()));
    })
}

#[test]
fn category_absent_on_ios_with_flag_clear_passes() -> TestResult {
    passes(|f| f.extensions = None)
}

#[test]
fn bundle_version_in_list_passes() -> TestResult {
    passes(|f| {
        accept_bundle_versions(f, &["0.9", "1.0"]);
        f.extensions = Some(bundle_and_category(cbor_text("1.0")));
    })
}

#[test]
fn mac_attestation_verifies() -> TestResult {
    let run = Fixture::valid_mac().run_all()?;
    require_verified(&run, "macOS fixture")?;
    assert!(run.ran.contains(&AppAttestCheck::AclBlob));
    Ok(())
}

#[test]
fn verified_carries_platform_entry_credential_and_minted_at() -> TestResult {
    let fixture = Fixture::valid();
    let built = fixture.build()?;
    let verified = fixture
        .run_all()?
        .result
        .map_err(|stop| format!("expected Verified, got {stop:?}"))?;
    assert_eq!(verified.platform(), DeviceAttestationPlatform::AppAttest);
    assert_eq!(verified.entry_id(), "entry-1");
    assert_eq!(
        verified.credential(),
        &<[u8; 32]>::from(Sha256::digest(built.leaf_point))
    );
    assert_eq!(verified.minted_at(), T0);
    Ok(())
}

// ── Platform path (AC25, AC29, B3) ──────────────────────────────────────────

fn path_of(mutate: fn(&mut Fixture)) -> BoxResult<Option<ApplePlatform>> {
    let mut fixture = Fixture::valid();
    mutate(&mut fixture);
    let built = fixture.build()?;
    Ok(choose_platform_path(&x509::parse_tbs(
        x509::split_certificate(&built.leaf)?.tbs,
    )?))
}

#[test]
fn choose_platform_path_on_test_ca_leaves() -> TestResult {
    assert_eq!(
        path_of(|f| f.platform = Some(platform_extension(b"macosx")))?,
        Some(ApplePlatform::MacOs)
    );
    assert_eq!(
        path_of(|f| f.platform = Some(platform_extension(b"iphoneos")))?,
        Some(ApplePlatform::Ios)
    );
    assert_eq!(path_of(|f| f.platform = None)?, Some(ApplePlatform::Ios));
    assert_eq!(
        path_of(|f| f.acl_blob = Some(acl_blob_extension(&MACOS_ACL_BLOB)))?,
        Some(ApplePlatform::MacOs)
    );
    assert_eq!(
        path_of(|f| f.platform = Some(platform_extension(b"watchos")))?,
        None
    );
    // An 8.7 without [1026], as iOS 14 through 17 write it.
    assert_eq!(
        path_of(|f| f.platform = Some(seq(&[&tlv(&[0xbf, 0x8a, 0x78], &octets(b"17.6.1"))])))?,
        Some(ApplePlatform::Ios)
    );
    Ok(())
}

#[test]
fn ios_path_never_runs_acl_blob_check() -> TestResult {
    for platform in [Some(platform_extension(b"iphoneos")), None] {
        let mut fixture = Fixture::valid();
        fixture.platform = platform;
        // No 8.6: the aclBlob comparison would fail if it ran.
        assert!(fixture.acl_blob.is_none());
        let run = fixture.run_all()?;
        require_verified(&run, "iOS leaf")?;
        assert!(
            !run.ran.contains(&AppAttestCheck::AclBlob),
            "ran {:?}",
            run.ran
        );
        assert!(run.ran.contains(&AppAttestCheck::PlatformPath));
    }
    Ok(())
}

#[test]
fn mac_attestation_against_ios_label_runs_acl_blob_before_app_id() -> TestResult {
    let mut fixture = Fixture::valid_mac();
    fixture.policy = policy_for(ApplePlatform::Ios);
    let run = fixture.run_all()?;
    assert_eq!(run.result, Err(Stop::Reject(R::PlatformMismatch)));
    let acl = run.ran.iter().position(|id| *id == AppAttestCheck::AclBlob);
    let app = run.ran.iter().position(|id| *id == AppAttestCheck::AppId);
    assert!(acl.is_some() && acl < app, "ran {:?}", run.ran);
    // A Mac leaf with a wrong aclBlob under an Ios label stops at the aclBlob.
    fixture.acl_blob = Some(acl_blob_extension(&[0u8; 66]));
    assert_eq!(
        fixture.run_all()?.result,
        Err(Stop::Reject(R::AclBlobMismatch))
    );
    Ok(())
}

#[test]
fn same_app_id_both_platforms_selects_path() -> TestResult {
    let both = |fixture: &mut Fixture| {
        fixture.policy.accepted_app_ids = vec![
            AcceptedAppId {
                app_id: crate::trust::device_attestation::test_ca::APP_ID.to_owned(),
                platform: ApplePlatform::Ios,
                accepted_bundle_versions: vec!["9.9".to_owned()],
            },
            AcceptedAppId {
                app_id: crate::trust::device_attestation::test_ca::APP_ID.to_owned(),
                platform: ApplePlatform::MacOs,
                accepted_bundle_versions: Vec::new(),
            },
        ];
    };
    // The iOS leaf selects the Ios element, whose version list it misses.
    let mut ios = Fixture::valid();
    both(&mut ios);
    assert_eq!(
        ios.run_all()?.result,
        Err(Stop::Reject(R::BundleVersionNotAccepted))
    );
    // The Mac leaf selects the MacOs element, whose list is empty.
    let mut mac_fixture = Fixture::valid_mac();
    both(&mut mac_fixture);
    require_verified(&mac_fixture.run_all()?, "Mac leaf, both elements")
}

// ── The pinned anchor ───────────────────────────────────────────────────────

/// §25.35 Vector 88: SHA-256 of Apple's App Attestation Root CA DER.
const APPLE_ROOT_SHA256_HEX: &str =
    "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932";

#[test]
fn pinned_root_fingerprint() -> TestResult {
    let pinned = APPLE_APP_ATTESTATION_ROOT.der();
    assert_eq!(hex::encode(Sha256::digest(pinned)), APPLE_ROOT_SHA256_HEX);
    // Any one-byte change moves the fingerprint.
    for index in [0, pinned.len() / 2, pinned.len() - 1] {
        let mut changed = pinned.to_vec();
        if let Some(byte) = changed.get_mut(index) {
            *byte ^= 0x01;
        }
        assert_ne!(hex::encode(Sha256::digest(&changed)), APPLE_ROOT_SHA256_HEX);
    }
    // The pinned root is a P-384 certificate the chain parser reads.
    let root = x509::parse_tbs(x509::split_certificate(pinned)?.tbs)?;
    assert!(matches!(root.key, x509::SubjectKey::P384(_)));
    Ok(())
}

#[test]
fn macos_acl_blob_is_the_spec_base64() -> TestResult {
    use base64::Engine as _;
    let spec = base64::engine::general_purpose::STANDARD.decode(
        "MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB",
    )?;
    assert_eq!(spec.as_slice(), MACOS_ACL_BLOB.as_slice());
    Ok(())
}

#[test]
fn test_ca_attestation_refused_by_public_reader() -> TestResult {
    let fixture = Fixture::valid();
    let built = fixture.build()?;
    let read = AppAttestRead {
        attestation_object: &built.object,
        binding_digest: fixture.binding_digest,
        policy: fixture.policy.validated()?,
        now_secs: fixture.now_secs,
        entry_id: "entry-1",
    };
    assert!(read_with_root(&AppAttestRoot::from_test_der(&built.root), &read).is_ok());
    assert_eq!(read_app_attest(&read), Err(R::CertificateChainInvalid));
    Ok(())
}

// ── Recorded Apple samples ──────────────────────────────────────────────────

const SAMPLES: [(&str, &[u8]); 3] = [
    ("ios-14.4", include_bytes!("samples/ios-14.4.cbor")),
    ("go-dev", include_bytes!("samples/go-dev.cbor")),
    ("go-prod", include_bytes!("samples/go-prod.cbor")),
];

fn sample_leaf(object: &[u8]) -> BoxResult<x509::Tbs> {
    let parts = lenient_object(object).ok_or("sample object did not decode")?;
    Ok(x509::parse_tbs(x509::split_certificate(&parts.leaf)?.tbs)?)
}

#[test]
fn recorded_sample_after_not_after() -> TestResult {
    let mut policy = policy_for(ApplePlatform::Ios);
    policy.device_attestation_max_age_secs =
        crate::trust::sybil::MAX_DEVICE_ATTESTATION_MAX_AGE_SECS;
    for (name, object) in SAMPLES {
        let leaf = sample_leaf(object)?;
        // A day after the leaf expired, and inside the maximum age.
        let now_secs = leaf.not_after + DAY;
        assert!(
            now_secs
                <= policy
                    .validated()?
                    .device_attestation_expiry(leaf.not_before),
            "{name}: the read is inside the maximum age"
        );
        let read = AppAttestRead {
            attestation_object: object,
            binding_digest: [0x5a; 32],
            policy: policy.validated()?,
            now_secs,
            entry_id: "entry-1",
        };
        assert_eq!(read_app_attest(&read), Err(R::NonceMismatch), "{name}");
        // Checks 1 through 4 passed against the pinned root: the run stopped
        // at check 5.
        let recorded = run(&APPLE_APP_ATTESTATION_ROOT, &read, &APP_ATTEST_CHECKS);
        assert_eq!(recorded.ran.last(), Some(&AppAttestCheck::Nonce), "{name}");
    }
    Ok(())
}

#[test]
fn recorded_sample_leaves_take_the_ios_path() -> TestResult {
    for (name, object) in SAMPLES {
        assert_eq!(
            choose_platform_path(&sample_leaf(object)?),
            Some(ApplePlatform::Ios),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn vendored_samples_pass_encoding_checks() -> TestResult {
    let policy = policy_for(ApplePlatform::Ios);
    let encoding_checks: Vec<(AppAttestCheck, CheckFn)> = APP_ATTEST_CHECKS
        .iter()
        .filter(|(id, _)| {
            matches!(
                id,
                AppAttestCheck::ObjectEncoding | AppAttestCheck::AuthData
            )
        })
        .copied()
        .collect();
    for (name, object) in SAMPLES {
        let canonical = canonicalize_app_attest_object(object)?;
        assert_eq!(
            canonicalize_app_attest_object(&canonical)?,
            canonical,
            "{name}: idempotent"
        );
        for input in [object, canonical.as_slice()] {
            let read = AppAttestRead {
                attestation_object: input,
                binding_digest: [0x5a; 32],
                policy: policy.validated()?,
                now_secs: T0,
                entry_id: "entry-1",
            };
            let recorded = run(&APPLE_APP_ATTESTATION_ROOT, &read, &encoding_checks);
            assert_eq!(
                recorded.ran,
                [AppAttestCheck::ObjectEncoding, AppAttestCheck::AuthData],
                "{name}: {:?}",
                recorded.result
            );
            assert!(recorded.result.is_ok(), "{name}: {:?}", recorded.result);
        }
    }
    Ok(())
}

// ── The owner's re-encoding ─────────────────────────────────────────────────

#[test]
fn canonicalize_drops_receipt_and_unknown_keys() -> TestResult {
    let mut fixture = Fixture::valid();
    let expected = fixture.build()?.object;
    fixture.object_hook = Some(byte_string_receipt);
    assert_eq!(
        canonicalize_app_attest_object(&fixture.build()?.object)?,
        expected
    );
    fixture.object_hook = Some(extra_top_level_key);
    assert_eq!(
        canonicalize_app_attest_object(&fixture.build()?.object)?,
        expected
    );
    // Out-of-order and long-head inputs come out canonical.
    fixture.object_hook = Some(top_level_out_of_order);
    assert_eq!(
        canonicalize_app_attest_object(&fixture.build()?.object)?,
        expected
    );
    fixture.object_hook = Some(long_x5c_byte_string_head);
    assert_eq!(
        canonicalize_app_attest_object(&fixture.build()?.object)?,
        expected
    );
    Ok(())
}

#[test]
fn canonicalize_refuses_malformed_objects() -> TestResult {
    let mut fixture = Fixture::valid();
    let valid = fixture.build()?.object;
    let mut trailing = valid.clone();
    trailing.push(0x00);
    assert_eq!(
        canonicalize_app_attest_object(&trailing),
        Err(AppAttestObjectError::NotWellFormed)
    );
    assert_eq!(
        canonicalize_app_attest_object(valid.get(..valid.len() - 1).unwrap_or_default()),
        Err(AppAttestObjectError::NotWellFormed)
    );
    let refused: [fn(&Built) -> Vec<u8>; 3] =
        [x5c_one_element, tagged_x5c_element, repeated_x5c_key];
    for hook in refused {
        fixture.object_hook = Some(hook);
        assert_eq!(
            canonicalize_app_attest_object(&fixture.build()?.object),
            Err(AppAttestObjectError::UnexpectedShape)
        );
    }
    // A tagged receipt is dropped with the receipt.
    fixture.object_hook = Some(tagged_receipt);
    assert_eq!(
        canonicalize_app_attest_object(&fixture.build()?.object)?,
        valid
    );
    let wrong_fmt = cbor_map(&[
        (cbor_text("fmt"), cbor_text("packed")),
        (
            cbor_text("attStmt"),
            cbor_map(&[(
                cbor_text("x5c"),
                cbor_array(&[cbor_bytes(b"a"), cbor_bytes(b"b")]),
            )]),
        ),
        (cbor_text("authData"), cbor_bytes(b"x")),
    ]);
    assert_eq!(
        canonicalize_app_attest_object(&wrong_fmt),
        Err(AppAttestObjectError::UnexpectedShape)
    );
    Ok(())
}
