//! Three members interoperate on ciphersuite 2
//! (`MLS_128_DHKEMP256_AES128GCM_SHA256_P256`, 09 §9.5).
//!
//! A creates the group and adds B, then C. A's message reaches B and C, and B's
//! reaches A and C. A removes C and B and C both process the removal; B still
//! decrypts A's next message and C, now inactive, cannot.
//! Every member's group runs cs2 and every leaf `signature_key` is a 65-byte
//! uncompressed P-256 point. Setting `SCP_CIPHERSUITE` back to ciphersuite 1
//! fails the ciphersuite and leaf-key assertions.

use openmls::prelude::{Ciphersuite, KeyPackageIn, SignatureScheme};
use scp_clock::SystemClock;
use scp_crypto::p256::testing::uncompressed_point_for;
use scp_did::SigningKeyId;
use scp_mls::encrypt::{decrypt, encrypt, serialize_ciphertext};
use scp_mls::epoch_grace::EpochGraceStore;
use scp_mls::ratchet::{process_commit, serialize_mls_message};
use scp_mls::{
    ScpCredential, ScpMlsGroup, add_member, create_group, generate_key_package, join_group,
    remove_member,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn credential(did: &str) -> TestResult<ScpCredential> {
    Ok(ScpCredential::new(
        did.to_owned(),
        None,
        SigningKeyId::Active,
    )?)
}

/// Generates a `KeyPackage` for `did` and returns it with the material the
/// joiner keeps for the Welcome.
fn key_package(
    did: &str,
) -> TestResult<(
    KeyPackageIn,
    scp_mls::SignatureKeyPair,
    scp_mls::InMemoryMlsProvider,
)> {
    let (bundle, signer, provider) = generate_key_package(
        &credential(did)?,
        &uncompressed_point_for(did),
        &SystemClock,
    )?;
    assert_eq!(
        bundle.key_package().ciphersuite(),
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    );
    Ok((bundle.key_package().clone().into(), signer, provider))
}

fn assert_cs2(group: &ScpMlsGroup) -> TestResult {
    assert_eq!(
        group.inner()?.ciphersuite(),
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    );
    assert_eq!(
        group.signer_key_pair()?.signature_scheme(),
        SignatureScheme::ECDSA_SECP256R1_SHA256
    );
    for member in group.members()? {
        assert_eq!(member.signature_key.len(), 65);
        assert_eq!(member.signature_key[0], 0x04);
    }
    Ok(())
}

fn send(group: &mut ScpMlsGroup, text: &[u8]) -> TestResult<Vec<u8>> {
    Ok(serialize_ciphertext(&encrypt(group, text)?)?)
}

#[test]
fn three_members_interoperate_on_cs2() -> TestResult {
    const A: &str = "did:dht:zCs2InteropAliceAAAAAAAAAAAAAAAAAAAAAAA";
    const B: &str = "did:dht:zCs2InteropBobBBBBBBBBBBBBBBBBBBBBBBBBB";
    const C: &str = "did:dht:zCs2InteropCarolCCCCCCCCCCCCCCCCCCCCCCC";

    let mut a = create_group(&credential(A)?, &uncompressed_point_for(A), &SystemClock)?;

    let (b_kp, b_signer, b_provider) = key_package(B)?;
    let add_b = add_member(&mut a, b_kp, &SystemClock)?;
    let mut b = join_group(&add_b.welcome, b_provider, b_signer)?;

    let (c_kp, c_signer, c_provider) = key_package(C)?;
    let add_c = add_member(&mut a, c_kp, &SystemClock)?;
    let mut b_grace = EpochGraceStore::new();
    process_commit(
        &mut b,
        &serialize_mls_message(&add_c.commit)?,
        &mut b_grace,
        &SystemClock,
    )?;
    let mut c = join_group(&add_c.welcome, c_provider, c_signer)?;

    for group in [&a, &b, &c] {
        assert_cs2(group)?;
        assert_eq!(group.members()?.len(), 3);
    }

    let from_a = send(&mut a, b"from A")?;
    assert_eq!(decrypt(&mut b, &from_a)?, b"from A");
    assert_eq!(decrypt(&mut c, &from_a)?, b"from A");

    let from_b = send(&mut b, b"from B")?;
    assert_eq!(decrypt(&mut a, &from_b)?, b"from B");
    assert_eq!(decrypt(&mut c, &from_b)?, b"from B");

    let c_leaf = c.own_leaf_index()?;
    let removal = remove_member(&mut a, c_leaf)?;
    let removal_bytes = serialize_mls_message(&removal.commit)?;
    process_commit(&mut b, &removal_bytes, &mut b_grace, &SystemClock)?;
    // C processes its own removal too, so the final assertion shows that C
    // is out of the group, not merely one epoch behind.
    let mut c_grace = EpochGraceStore::new();
    process_commit(&mut c, &removal_bytes, &mut c_grace, &SystemClock)?;
    assert!(
        !c.inner()?.is_active(),
        "C must be inactive after its removal"
    );
    assert_eq!(a.members()?.len(), 2);
    assert_eq!(b.members()?.len(), 2);
    assert!(
        !a.members()?.into_iter().any(|m| m.index == c_leaf),
        "the removal targeted C's leaf"
    );

    let after_removal = send(&mut a, b"after removal")?;
    assert_eq!(decrypt(&mut b, &after_removal)?, b"after removal");
    assert!(decrypt(&mut c, &after_removal).is_err());
    Ok(())
}
