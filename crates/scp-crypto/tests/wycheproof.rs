//! Wycheproof conformance for the P-256 primitives in `scp_crypto::p256`.
//!
//! The vector files are vendored verbatim from C2SP/wycheproof at commit
//! [`UPSTREAM_COMMIT`], path `testvectors_v1/`. Each file's SHA-256 is pinned
//! below and checked before its vectors run, so an edited or re-fetched file
//! fails loudly instead of silently changing what is tested.
//!
//! Every case must reach its expected outcome, and every file must run exactly
//! its declared `numberOfTests`, so a skipped case is a failure too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use scp_crypto::p256::{
    P256Error, P256PublicKey, P256SigningKey, der_to_raw, ecdh_p256, verify_prehash_lenient,
    verify_prehash_strict,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// C2SP/wycheproof commit the vectors were copied from (2026-09-02).
const UPSTREAM_COMMIT: &str = "3fa63dd0344abb611f1fb1d77e119938603ea230";

const ECDH_FILE: (&str, &str) = (
    "ecdh_secp256r1_ecpoint_test.json",
    "648f16d077caf2400d02331ca51f44744c72c799830c8d0595d0b18b6dd9f886",
);
const P1363_FILE: (&str, &str) = (
    "ecdsa_secp256r1_sha256_p1363_test.json",
    "c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986",
);
const DER_FILE: (&str, &str) = (
    "ecdsa_secp256r1_sha256_test.json",
    "182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332",
);

/// Reads a vendored file, checks its pinned SHA-256, and returns the parsed
/// JSON and its declared test count.
fn load((name, sha256): (&str, &str)) -> (Value, usize) {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "wycheproof", name]
        .iter()
        .collect();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        sha256,
        "{name} does not match the file vendored from wycheproof {UPSTREAM_COMMIT}"
    );
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    let declared = usize::try_from(json["numberOfTests"].as_u64().unwrap()).unwrap();
    (json, declared)
}

fn tests(json: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    json["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["tests"].as_array().unwrap().iter().map(move |t| (g, t)))
}

fn hexf(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

/// Wycheproof private keys are minimal two's-complement integers: strip the
/// sign byte and left-pad to 32 bytes.
fn scalar32(bytes: &[u8]) -> [u8; 32] {
    let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    assert!(trimmed.len() <= 32);
    let mut out = [0u8; 32];
    out[32 - trimmed.len()..].copy_from_slice(&trimmed);
    out
}

#[test]
fn ecdh_secp256r1_ecpoint() {
    let (json, declared) = load(ECDH_FILE);
    let mut ran = 0;
    for (_, t) in tests(&json) {
        ran += 1;
        let id = &t["tcId"];
        let parsed = P256PublicKey::from_sec1(&hexf(&t["public"]));
        match t["result"].as_str().unwrap() {
            // "acceptable" is tcId 2, a compressed public key, which §9.5
            // accepts for a verification key; it must then agree correctly.
            "valid" | "acceptable" => {
                let peer = parsed.unwrap_or_else(|e| panic!("tcId {id}: {e}"));
                let key =
                    P256SigningKey::from_scalar_bytes(&scalar32(&hexf(&t["private"]))).unwrap();
                assert_eq!(
                    ecdh_p256(&key, &peer).to_vec(),
                    hexf(&t["shared"]),
                    "tcId {id}"
                );
            }
            // Every invalid case is a bad point: off-curve, twist, empty, or a
            // compressed x with no y. Point validation must reject it.
            "invalid" => assert!(parsed.is_err(), "tcId {id} must fail point validation"),
            other => panic!("tcId {id}: unknown result {other}"),
        }
    }
    assert_eq!(ran, declared);
}

/// Checks one signature both ways. Wycheproof's `valid` follows plain ECDSA,
/// which admits high `s`, so the lenient verifier must agree with it exactly,
/// and the strict verifier must agree except that it rejects high `s`.
fn check_signature(pk: &P256PublicKey, digest: &[u8; 32], sig: &[u8], valid: bool, id: &Value) {
    let lenient = verify_prehash_lenient(pk, digest, sig);
    let strict = verify_prehash_strict(pk, digest, sig);
    if valid {
        lenient.unwrap_or_else(|e| panic!("tcId {id}: lenient rejected a valid signature: {e}"));
        // Fixed-width big-endian byte order is integer order, so this compares
        // the full integer `s` against (n − 1)/2.
        let high_s = sig[32..] > HALF_N[..];
        match strict {
            Ok(()) => assert!(!high_s, "tcId {id}: strict accepted s > (n-1)/2"),
            Err(P256Error::HighS) => {
                assert!(high_s, "tcId {id}: strict called s <= (n-1)/2 high");
            }
            Err(e) => panic!("tcId {id}: strict rejected a valid low-s signature: {e}"),
        }
    } else {
        assert!(
            lenient.is_err(),
            "tcId {id}: lenient accepted an invalid signature"
        );
        assert!(
            strict.is_err(),
            "tcId {id}: strict accepted an invalid signature"
        );
    }
}

/// `(n − 1)/2` for P-256, the largest `s` §9.5 admits (SEC 2 `n`, halved).
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

fn group_key(g: &Value) -> P256PublicKey {
    assert_eq!(g["sha"], "SHA-256");
    P256PublicKey::from_sec1(&hexf(&g["publicKey"]["uncompressed"])).unwrap()
}

#[test]
fn ecdsa_secp256r1_sha256_p1363() {
    let (json, declared) = load(P1363_FILE);
    let mut ran = 0;
    for (g, t) in tests(&json) {
        ran += 1;
        let digest: [u8; 32] = Sha256::digest(hexf(&t["msg"])).into();
        let valid = match t["result"].as_str().unwrap() {
            "valid" => true,
            "invalid" => false,
            other => panic!("unexpected result {other}"),
        };
        check_signature(&group_key(g), &digest, &hexf(&t["sig"]), valid, &t["tcId"]);
    }
    assert_eq!(ran, declared);
}

#[test]
fn ecdsa_secp256r1_sha256_der() {
    let (json, declared) = load(DER_FILE);
    let mut ran = 0;
    for (g, t) in tests(&json) {
        ran += 1;
        let id = &t["tcId"];
        let digest: [u8; 32] = Sha256::digest(hexf(&t["msg"])).into();
        let raw = der_to_raw(&hexf(&t["sig"]));
        match t["result"].as_str().unwrap() {
            "valid" => {
                let raw = raw.unwrap_or_else(|e| panic!("tcId {id}: strict DER rejected: {e}"));
                check_signature(&group_key(g), &digest, &raw, true, id);
            }
            // An invalid case fails either at the strict DER parse (BER,
            // missing or extra zeros, wrong types, trailing data) or at
            // verification.
            "invalid" => {
                if let Ok(raw) = raw {
                    check_signature(&group_key(g), &digest, &raw, false, id);
                }
            }
            other => panic!("tcId {id}: unexpected result {other}"),
        }
    }
    assert_eq!(ran, declared);
}
